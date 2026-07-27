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

            while (BIO_pending(ssl.wbio) > 0)
            {
                std::pair<std::array<char, BUFFER_SIZE>, int> chunk;
                int bytes = BIO_read(ssl.wbio, chunk.first.data(), BUFFER_SIZE);

                if (bytes > 0)
                {
                    chunk.second = bytes;
                    conn.writeQueue.push_back(std::move(chunk));
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
                int n = BIO_write(ssl.rbio, conn.in_raw_buffer, res);

                int bytes = SSL_read(ssl.ssl, conn.in_plain_buffer, BUFFER_SIZE);
                if (bytes > 0)
                {
                    conn.in_len = bytes;
                }
            }

            if (conn.peerFd == -1)
            {
                // std::string host = Utils::Http::getHost(Gen::activeThreads[thread].ssl[conn.fd].handshakeDone ? conn.in_plain_buffer : conn.in_raw_buffer, res);
                // std::string ip = Main::dns->getRandomIP(host);

                /*if (!Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
                {
                    std::string path = Utils::Http::getPath(conn.in_raw_buffer, res);

                    if (memcmp(path.data(), "/.well-known/acme-challenge/", 28) == 0)
                    {
                        std::string token = path.data() + 28;

                        std::string authorizationKey = Origin::getAcmeToken(host, token);
                        if (authorizationKey.empty())
                            authorizationKey = "UNAUTHORIZED";

                        std::string res =
                            "HTTP/1.1 502 Bad Gateway\r\n"
                            "Content-Type: text/plain; charset=UTF-8\r\n"
                            "Content-Length: " +
                            std::to_string(authorizationKey.size()) + "\r\n"
                                                                      "Connection: close\r\n"
                                                                      "Server: EdgeOn-Proxy/1.0\r\n"
                                                                      "\r\n" +
                            authorizationKey.data();

                        std::pair<std::array<char, BUFFER_SIZE>, int> chunk;
                        memcpy(chunk.first.data(), res.data(), res.size());
                        chunk.second = chunk.first.size();

                        conn.writeQueue.push_back(std::move(chunk));

                        pipeline->queueWriteClient(conn);
                        io_uring_submit(ring);

                        break;
                    }
                }*/

                int peerFd = -1;

                peerFd = Proxy::createOriginSocket("127.0.0.1", 3000);

                // if (!ip.empty())
                // peerFd = Proxy::createOriginSocket((char *)ip.c_str(), 80);

                if (peerFd == -1)
                {
                    conn.backendIsUnreachable = true;

                    std::string page = Pages::getPage("pages/502.html");

                    std::string req =
                        "HTTP/1.1 502 Bad Gateway\r\n"
                        "Content-Type: text/html; charset=UTF-8\r\n"
                        "Content-Length: " +
                        std::to_string(page.size()) + "\r\n"
                                                      "Connection: close\r\n"
                                                      "Server: EdgeOn-Proxy/1.0\r\n"
                                                      "\r\n" +
                        page;

                    int offset = 0;
                    while (offset < req.size())
                    {
                        ssize_t len = std::min(BUFFER_SIZE - 256, int(req.size() - offset));

                        std::pair<std::array<char, BUFFER_SIZE>, int> chunk;

                        if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
                        {
                            SSL_write(Gen::activeThreads[thread].ssl[conn.fd].ssl, req.data() + offset, len);
                            int bytes = BIO_read(Gen::activeThreads[thread].ssl[conn.fd].wbio, chunk.first.data(), BUFFER_SIZE);
                            chunk.second = bytes;
                        }
                        else
                        {
                            memcpy(chunk.first.data(), req.data() + offset, len);
                            chunk.second = chunk.first.size();
                        }

                        conn.writeQueue.push_back(std::move(chunk));

                        offset += len;
                    }

                    pipeline->queueWriteClient(conn);
                    io_uring_submit(ring);

                    break;
                }

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
            if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
            {
                auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];

                SSL_write(ssl.ssl, conn.out_plain_buffer, res);
                while (BIO_pending(ssl.wbio) > 0)
                {
                    std::pair<std::array<char, BUFFER_SIZE>, int> chunk;
                    int bytes = BIO_read(ssl.wbio, chunk.first.data(), BUFFER_SIZE);
                    chunk.second = bytes;

                    conn.writeQueue.push_back(std::move(chunk));
                }
            }

            pipeline->queueWriteClient(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_READ_ORIGIN;
            break;
        }

        case Gen::STATE_WRITE_CLIENT:
        {
            if (!conn.writeQueue.empty())
            {
                conn.writeOffset += res;

                if (conn.writeOffset >= conn.writeQueue.front().second)
                {
                    conn.writeQueue.pop_front();
                    conn.writeOffset = 0;
                }

                if (!conn.writeQueue.empty())
                {
                    pipeline->queueWriteClient(conn);
                    io_uring_submit(ring);
                    break;
                }
            }

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