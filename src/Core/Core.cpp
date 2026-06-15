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
    struct io_uring *ring = Gen::activeThreads[thread].ring;
    if (io_uring_queue_init(QUEUE_DEPTH, ring, 0) < 0)
    {
        perror("uring queue init failed.");
        return;
    }

    Pipeline *pipeline = new Pipeline(ring, thread);

    // Port inits
    for (int port : Main::listeners)
    {
        pipeline->queueMultishotAccept(port);
    }

    while (!Gen::activeThreads[thread].isShutdown)
    {
        struct io_uring_cqe *cqe;
        int ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0)
            break;

        uint64_t data = (uint64_t)io_uring_cqe_get_data(cqe);
        int fd = (int)(data & 0xFFFFFFFF);
        int opType = (int)(data >> 32);

        switch (opType)
        {
        case Gen::STATE_ACCEPT_MULTSHOT:
        {
            break;
        }
        }
    }

    Gen::activeThreads.erase(thread);
}