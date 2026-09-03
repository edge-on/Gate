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

    int udpFd = Proxy::initUdpServer(443);
    Gen::activeThreads[thread].udpFd = udpFd;

    Pipeline::H1 *pipelineH1 = new Pipeline::H1(ring, thread);
    Pipeline::H3 *pipelineH3 = new Pipeline::H3(ring, thread, Gen::activeThreads[thread].udpFd);

    Protocols::H1 *h1 = new Protocols::H1(ring, thread, pipelineH1, ctx);
    Protocols::H3 *h3 = new Protocols::H3(ring, thread, pipelineH3, quicheConf, quicheCtx);

    pipelineH3->queueReadClient();

    // Port inits
    for (int port : Main::listeners)
    {
        int fd = Proxy::initServer(port);
        Gen::activeThreads[thread].listeners.emplace(port, fd);
        pipelineH1->queueMultishotAccept(fd);
    }

    Gen::activeThreads[thread].wakeup.init();

    auto *sqe = Utils::Uring::getSqe(ring);
    uint64_t data = ((uint64_t)Gen::STATE_TLS_WAKEUP << 32) |
                    (((uint64_t)0 & 0x0FFFFFFF) << 4) |
                    ((uint64_t)Gen::H1 & 0xF);
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
        int opType = (int)(data >> 32);
        int id = (int)((data >> 4) & 0x0FFFFFFF);
        int protocol = (int)(data & 0xF);

        int res = cqe->res;

        int result = -1;

        if (opType == Gen::STATE_TLS_WAKEUP)
        {
            if (protocol == Gen::H3)
                h1->wakeup(res);
            else
                h1->wakeup(res);

            continue;
        }

        if (protocol == Gen::H3)
            result = h3->run(cqe);
        else
            result = h1->run(cqe);

        if (result == Gen::CONTINUE)
            continue;
    }
}