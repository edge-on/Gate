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
        Gen::activeThreads[thread].listeners.emplace(port, fd);
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
            tempConn.type == Gen::TYPE_CLIENT;
            Gen::activeThreads[thread].connections.emplace(clientFd, std::move(tempConn));

            auto &conn = Gen::activeThreads[thread].connections[clientFd];

            if (fd == Gen::activeThreads[thread].listeners[80])
            {
                conn.protocolState = Gen::TCP_RAW;

                pipeline->queueReadClient(conn);
                io_uring_submit(ring);
            }
            else if (fd == Gen::activeThreads[thread].listeners[443])
            {
                auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];

                ssl.ssl = SSL_new(ctx);
                ssl.rbio = BIO_new(BIO_s_mem());
                ssl.wbio = BIO_new(BIO_s_mem());

                conn.protocolState = Gen::TCP_TLS;

                SSL_set_bio(ssl.ssl, ssl.rbio, ssl.wbio);
                SSL_set_accept_state(ssl.ssl);

                pipeline->queueTlsConnecting(conn);
                io_uring_submit(ring);
            }

            if (!hasMore)
            {
                pipeline->queueMultishotAccept(fd);
                io_uring_submit(ring);
            }

            conn.lastOpType = Gen::STATE_ACCEPT_MULTISHOT;

            continue;
        }

        auto it = Gen::activeThreads[thread].connections.find(fd);
        if (it == Gen::activeThreads[thread].connections.end())
            continue;

        Gen::Connection &conn = it->second;

        switch (opType)
        {
        case Gen::STATE_TLS_CONNECTING:
        {
            auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];

            BIO_write(ssl.rbio, conn.in_raw_buffer, res);

            if (SSL_accept(ssl.ssl) > 0)
            {
                ssl.handshakeDone = true;

                const unsigned char *alpn_proto;
                unsigned int alpn_len;
                SSL_get0_alpn_selected(ssl.ssl, &alpn_proto, &alpn_len);

                if (alpn_len > 0)
                {
                    std::string selected_proto((char *)alpn_proto, alpn_len);

                    if (selected_proto == "h2")
                    {
                        conn.protocol = Gen::H2;
                    }
                    else
                    {
                        conn.protocol = Gen::H1;
                    }
                }
                else
                {
                    conn.protocol = Gen::H1;
                }
            }

            if (ssl.handshakeDone)
            {
                pipeline->queueReadClient(conn);
                io_uring_submit(ring);

                conn.lastOpType = Gen::STATE_TLS_CONNECTING;

                break;
            }

            if (BIO_pending(ssl.wbio) > 0)
            {
                int bytes = BIO_read(ssl.wbio, conn.out_raw_buffer, BUFFER_SIZE);

                if (bytes > 0)
                {
                    conn.out_len = bytes;
                    pipeline->queueWriteClient(conn);
                }
            }

            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_TLS_CONNECTING;
            break;
        }

        case Gen::STATE_READ_CLIENT:
        {
            conn.in_len = res;

            // TCP TLS
            if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
            {
                auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];
                BIO_write(ssl.rbio, conn.in_raw_buffer, res);

                int bytes = SSL_read(ssl.ssl, conn.in_plain_buffer, BUFFER_SIZE);
                if (bytes > 0)
                {
                    conn.in_len = bytes;
                }
            }

            if (conn.peerFd == -1)
            {
                std::string host = Utils::Http::getHost(conn.in_plain_buffer, res);

                int peerFd = Proxy::createOriginSocket("127.0.0.1", 3000);
                if (peerFd == -1)
                    break;

                Gen::Connection peerConn{};
                peerConn.fd = peerFd;
                peerConn.peerFd = conn.fd;
                conn.peerFd = peerFd;
                peerConn.type = Gen::TYPE_ORIGIN;

                Gen::activeThreads[thread].connections.emplace(peerFd, std::move(peerConn));

                pipeline->queueReadOrigin(conn);
            }

            pipeline->queueWriteOrigin(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_READ_CLIENT;

            break;
        }

        case Gen::STATE_WRITE_ORIGIN:
        {

            conn.lastOpType = Gen::STATE_WRITE_ORIGIN;
            break;
        }

        case Gen::STATE_READ_ORIGIN:
        {
            conn.out_len = res;

            if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
            {
                auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];

                SSL_write(ssl.ssl, conn.out_plain_buffer, res);
                if (BIO_pending(ssl.wbio) > 0)
                {
                    int bytes = BIO_read(ssl.wbio, conn.out_raw_buffer, BUFFER_SIZE);

                    conn.out_len = bytes;
                }
            }

            pipeline->queueWriteClient(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_READ_ORIGIN;
            break;
        }

        case Gen::STATE_WRITE_CLIENT:
        {
            if (conn.lastOpType == Gen::STATE_TLS_CONNECTING)
            {
                // If this write request come from tls connecting, we will back to tls connecting state
                pipeline->queueTlsConnecting(conn);
                io_uring_submit(ring);
            }
            else
            {
                pipeline->queueReadClient(conn);
                pipeline->queueReadOrigin(conn);
                io_uring_submit(ring);
            }

            conn.lastOpType = Gen::STATE_WRITE_CLIENT;
            break;
        }

        case Gen::STATE_POLL_ADD:
        {
            conn.lastOpType = Gen::STATE_POLL_ADD;
            break;
        }
        }
    }
}