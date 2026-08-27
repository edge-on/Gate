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
    ctx = Ssl::initSSL();

    Gen::zones.replaceCtx(Gen::zones.findOrCreate("localhost"), ctx);

    int threadCount = std::stoi(Main::dotenv->map["concurrency"]) + 1;

    for (int i = 0; i < threadCount; ++i)
    {
        if (i + 1 == threadCount)
            Gen::threads.emplace_back(&Thread::Operational::operationalWorker, i);
        else
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

    Pipeline::H1 *pipeline = new Pipeline::H1(ring, thread);

    // Port inits
    for (int port : Main::listeners)
    {
        int fd = Proxy::initServer(port);
        Gen::activeThreads[thread].listeners.emplace(port, fd);
        pipeline->queueMultishotAccept(fd);

        if (port == 443)
        {
            int udpFd = Proxy::initUdpServer(port);
            Gen::activeThreads[thread].udpFd = udpFd;
        }
    }

    Gen::activeThreads[thread].wakeup.init();

    auto *sqe = Utils::Uring::getSqe(ring);
    uint64_t data = ((uint64_t)Gen::STATE_TLS_WAKEUP << 32) | (uint32_t)0;
    io_uring_prep_poll_multishot(sqe, Gen::activeThreads[thread].wakeup.eventFd, POLLIN);
    io_uring_sqe_set_data(sqe, (void *)data);

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

        int result = -1;

        if (fd != Gen::activeThreads[thread].udpFd)
            result = Protocols::H1::run(cqe, ring, thread, pipeline, ctx);

        if (result == Gen::CONTINUE)
            continue;
    }
}