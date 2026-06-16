#include "Core/Core.hpp"

Core::Core()
{
}

Core::~Core()
{
    for (auto &thread : Gen::activeThreads)
    {
        thread.second.isShutdown = true;
    }
}

void Core::start()
{
    int threadCount = std::stoi(Main::dotenv->map["concurrency"]);

    for (int i = 0; i < threadCount; ++i)
    {
        Gen::threads.emplace_back(&Core::worker, this, i);
        Gen::activeThreads[i].id = Gen::threads[i].get_id();
    }

    for (auto &thread : Gen::threads)
    {
        thread.join();
    }
}

void Core::worker(int thread)
{
    struct io_uring *ring = &Gen::activeThreads[thread].ring;
    if (io_uring_queue_init(QUEUE_DEPTH, ring, 0) < 0)
    {
        perror("uring queue init failed.");
        return;
    }

    Pipeline *pipeline = new Pipeline(ring, thread);

    // Port inits
    for (int port : Main::listeners)
    {
        int fd = Proxy::initServer(port);
        pipeline->queueMultishotAccept(fd);
    }

    io_uring_submit(ring);

    while (!Gen::activeThreads[thread].isShutdown)
    {
        struct io_uring_cqe *cqe;
        int ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0)
            break;

        uint64_t data = (uint64_t)io_uring_cqe_get_data(cqe);
        int fd = (int)(data & 0xFFFFFFFF);
        int opType = (int)(data >> 32);

        int res = cqe->res;
        bool hasMore = cqe->flags & IORING_CQE_F_MORE;
        io_uring_cqe_seen(ring, cqe);

        if (res < 0)
        {
            auto it = Gen::activeThreads[thread].connections.find(fd);
            if (it != Gen::activeThreads[thread].connections.end())
            {
                Utils::Uring::closeConn(thread, it->second);
            }

            if (opType == Gen::STATE_ACCEPT_MULTISHOT)
            {
                pipeline->queueMultishotAccept(fd);
                io_uring_submit(ring);
            }

            continue;
        }

        if (opType == Gen::STATE_ACCEPT_MULTISHOT)
        {
            int clientFd = res;

            Gen::Connection tempConn;
            tempConn.fd = clientFd;
            Gen::activeThreads[thread].connections.emplace(clientFd, std::move(tempConn));

            auto &conn = Gen::activeThreads[thread].connections[clientFd];

            pipeline->queueReadClient(conn);
            io_uring_submit(ring);

            if (!hasMore)
            {
                pipeline->queueMultishotAccept(fd);
                io_uring_submit(ring);
            }

            continue;
        }

        auto it = Gen::activeThreads[thread].connections.find(fd);
        if (it == Gen::activeThreads[thread].connections.end())
            continue;

        Gen::Connection &conn = it->second;

        std::string a = "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n<h1>Hello</h1>";
        
        switch (opType)
        {
        case Gen::STATE_READ_CLIENT:
        {
            memcpy(conn.out_raw_buffer, a.data(), a.size());
            conn.out_len = a.size();

            pipeline->queueWriteClient(conn);
            io_uring_submit(ring);
            break;
        }

        case Gen::STATE_WRITE_CLIENT:
        {
            pipeline->queueReadClient(conn);
            io_uring_submit(ring);
            break;
        }
        }
    }
}