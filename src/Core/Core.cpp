#include "Core/Core.hpp"

Core::Core()
{
}

Core::~Core()
{
    for (auto &thread : Gen::Global::activeThreads)
    {
        thread.second.isShutdown = true;
    }
}

void Core::start()
{
    ctx = Ssl::initSSL();
    quicheConf = Ssl::initQuicheSSL();
    
    Gen::Global::zones.replaceCtx(Gen::Global::zones.findOrCreate("localhost"), ctx);

    int threadCount = std::stoi(Main::dotenv->map["concurrency"]) + 1;

    for (int i = 0; i < threadCount; ++i)
    {
        if (i + 1 == threadCount)
            Gen::Global::threads.emplace_back(&Thread::Operational::operationalWorker, i);
        else
            Gen::Global::threads.emplace_back(&Core::worker, this, i);

        Gen::Global::activeThreads[i].id = Gen::Global::threads[i].get_id();
    }

    for (auto &thread : Gen::Global::threads)
    {
        thread.join();
    }
}

void Core::worker(int thread)
{
    struct io_uring *ring = &Gen::Global::activeThreads[thread].ring;
    if (io_uring_queue_init(QUEUE_DEPTH, ring, 0) < 0)
    {
        perror("uring queue init failed.");
        return;
    }

    Pipeline::H1 *pipelineH1 = new Pipeline::H1(ring, thread);
    Pipeline::H3 *pipelineH3 = new Pipeline::H3(ring, thread);

    // Port inits
    for (int port : Main::listeners)
    {
        int fd = Proxy::initServer(port);
        Gen::Global::activeThreads[thread].listeners.emplace(port, fd);
        pipelineH1->queueMultishotAccept(fd);

        if (port == 443)
        {
            int udpFd = Proxy::initUdpServer(port);
            Gen::Global::activeThreads[thread].udpFd = udpFd;
        }
    }

    Gen::Global::activeThreads[thread].wakeup.init();

    auto *sqe = Utils::H1::Uring::getSqe(ring);
    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_TLS_WAKEUP << 32) | (uint32_t)0;
    io_uring_prep_poll_multishot(sqe, Gen::Global::activeThreads[thread].wakeup.eventFd, POLLIN);
    io_uring_sqe_set_data(sqe, (void *)data);

    io_uring_submit(ring);

    while (!Gen::Global::activeThreads[thread].isShutdown)
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

        if (fd == Gen::Global::activeThreads[thread].udpFd)
            result = Protocols::H1::run(cqe, ring, thread, pipelineH1, ctx);
        else
            result = Protocols::H1::run(cqe, ring, thread, pipelineH1, ctx);

        if (result == Gen::Global::CONTINUE)
            continue;
    }
}