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
    quicheConf = Ssl::initQuicheSSL();
    quicheCtx = (SSL_CTX *)quiche_config_get_ssl_ctx(quicheConf);

    SSL_CTX_set_select_certificate_cb(quicheCtx, Ssl::client_hello_cb);

    Gen::zones.replaceCtx(Gen::zones.findOrCreate("localhost"), ctx);

    int threadCountH1 = std::stoi(Main::dotenv->map["concurrencyH1"]);
    int h1 = 0;
    int threadCountH3 = std::stoi(Main::dotenv->map["concurrencyH3"]);
    int h3 = 0;

    isH3Active = threadCountH3 >= 1;
    isH1Active = threadCountH1 >= 1;

    int threadCount = threadCountH1 + threadCountH3 + 1;

    std::cout << " ================ THEADS ================ " << std::endl;

    for (int i = 0; i < threadCount; ++i)
    {
        if (h1 < threadCountH1)
        {
            h1++;
            Gen::activeThreads[i].protocol = Gen::H1;
            Gen::threads.emplace_back(&Core::workerH1, this, i);
            std::cout << "[" << Gen::threads[i].get_id() << "] - " << "HTTP/1.1 Thread Initialized" << std::endl;
        }
        else if (h3 < threadCountH3)
        {
            h3++;
            Gen::activeThreads[i].protocol = Gen::H3;
            Gen::threads.emplace_back(&Core::workerH3, this, i);
            std::cout << "[" << Gen::threads[i].get_id() << "] - " << "HTTP/3 Thread Initialized" << std::endl;
        }
        else
        {
            Gen::threads.emplace_back(&Thread::Operational::operationalWorker, i);
            std::cout << "[" << Gen::threads[i].get_id() << "] - " << "Operational Thread Initialized" << std::endl;
        }

        Gen::activeThreads[i].id = Gen::threads[i].get_id();
    }

    std::cout << " ================ WORKERS ================ " << std::endl;

    for (auto &thread : Gen::threads)
    {
        thread.join();
    }
}

void Core::workerH1(int thread)
{
    struct io_uring *ring = &Gen::activeThreads[thread].ring;
    if (io_uring_queue_init(QUEUE_DEPTH, ring, 0) < 0)
    {
        perror("uring queue init failed.");
        return;
    }

    Pipeline::H1 *pipelineH1 = new Pipeline::H1(ring, thread);

    Protocols::H1 *h1 = new Protocols::H1(ring, thread, pipelineH1, ctx);

    // Port inits
    for (int port : Main::listeners)
    {
        int fd = Proxy::initServer(port);
        Gen::activeThreads[thread].listeners.emplace(port, fd);
        pipelineH1->queueMultishotAccept(fd);
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

        io_uring_cqe_seen(ring, cqe);

        int res = cqe->res;

        int result = -1;

        if (opType == Gen::STATE_TLS_WAKEUP)
        {
            h1->wakeup(res);
            continue;
        }

        result = h1->run(cqe);

        if (result == Gen::CONTINUE)
            continue;
    }
}

void Core::workerH3(int thread)
{
    struct io_uring *ring = &Gen::activeThreads[thread].ring;
    if (io_uring_queue_init(QUEUE_DEPTH, ring, 0) < 0)
    {
        perror("uring queue init failed.");
        return;
    }

    int udpFd = Proxy::initUdpServer(443);
    Gen::activeThreads[thread].udpFd = udpFd;

    Pipeline::H3 *pipelineH3 = new Pipeline::H3(ring, thread, Gen::activeThreads[thread].udpFd);
    Protocols::H3 *h3 = new Protocols::H3(ring, thread, pipelineH3, quicheConf, quicheCtx);

    pipelineH3->queueReadClient();

    Gen::activeThreads[thread].wakeup.init();

    auto *sqe = Utils::Uring::getSqe(ring);
    uint64_t data = Gen::STATE_TLS_WAKEUP;
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
        int opType = (int)data;

        io_uring_cqe_seen(ring, cqe);

        int res = cqe->res;

        int result = -1;

        if (opType == Gen::STATE_TLS_WAKEUP)
        {
            continue;
        }

        result = h3->run(cqe);

        if (result == Gen::CONTINUE)
            continue;
    }
}