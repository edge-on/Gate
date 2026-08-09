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
    std::vector<char> memory_hog((1.5 * 1024 * 1024 * 1024), 1);

    ctx = Ssl::initSSL();

    int threadCount = std::stoi(Main::dotenv->map["concurrency"]) + 1;

    for (int i = 0; i < threadCount; ++i)
    {
        if (i + 1 == threadCount)
            Gen::threads.emplace_back(&Core::memoryWorker, this, i);
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
            if (opType == Gen::STATE_CONNECT_RESOLVER || opType == Gen::STATE_WRITE_RESOLVER || opType == Gen::STATE_READ_RESOLVER)
            {
                Gen::Connection &conn = Gen::activeThreads[thread].connections[fd];
                close(conn.resolverFd);
                pipeline->write502Page(conn);

                if (!conn.isWritingClient)
                {
                    conn.isWritingClient = true;
                    pipeline->queueWriteClient(conn);
                }
                io_uring_submit(ring);

                continue;
            }

            if (opType == Gen::STATE_ORIGIN_CONNECTING)
            {
                Gen::Connection &conn = Gen::activeThreads[thread].connections[fd];
                Gen::Connection &originConn = Gen::activeThreads[thread].connections[conn.peerFd];
                pipeline->write502Page(conn);

                Utils::Uring::closeConn(thread, originConn);
                conn.peerFd = -1;

                if (!conn.isWritingClient)
                {
                    conn.isWritingClient = true;
                    pipeline->queueWriteClient(conn);
                }
                io_uring_submit(ring);

                continue;
            }

            auto it = Gen::activeThreads[thread].connections.find(fd);
            if (it != Gen::activeThreads[thread].connections.end())
            {
                auto peerIt = Gen::activeThreads[thread].connections.find(it->second.peerFd);
                if (peerIt != Gen::activeThreads[thread].connections.end())
                {
                    Utils::Uring::closeConn(thread, peerIt->second);
                }

                Utils::Uring::closeConn(thread, it->second);
            }

            if (opType == Gen::STATE_ACCEPT_MULTISHOT)
            {
                pipeline->queueMultishotAccept(fd);
                io_uring_submit(ring);
            }

            continue;
        }

        // ===========================================
        //                SOCKET
        // ===========================================
        if (opType == Gen::STATE_ACCEPT_MULTISHOT)
        {
            int clientFd = res;

            Gen::Connection tempConn{};
            tempConn.fd = clientFd;
            tempConn.type = Gen::TYPE_CLIENT;

            Gen::activeThreads[thread].connections.erase(clientFd);
            Gen::activeThreads[thread].connections.emplace(clientFd, std::move(tempConn));

            auto &conn = Gen::activeThreads[thread].connections[clientFd];

            if (fd == Gen::activeThreads[thread].listeners[80])
            {
                conn.protocolState = Gen::TCP_RAW;

                pipeline->queueReadClient(conn);
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
            }

            if (!hasMore)
            {
                pipeline->queueMultishotAccept(fd);
            }

            io_uring_submit(ring);
            conn.lastOpType = Gen::STATE_ACCEPT_MULTISHOT;

            continue;
        }

        auto it = Gen::activeThreads[thread].connections.find(fd);
        if (it == Gen::activeThreads[thread].connections.end())
            continue;

        Gen::Connection &conn = it->second;

        switch (opType)
        {
        // ===========================================
        //                CLIENT
        // ===========================================
        case Gen::STATE_TLS_CONNECTING:
        {
            conn.isReadingClient = false;

            if (res == 0)
            {
                Utils::Uring::closeConn(thread, conn);
                io_uring_submit(ring);
                break;
            }

            auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];

            BIO_write(ssl.rbio, conn.in_raw_buffer, res);

            int r = SSL_accept(ssl.ssl);
            if (r > 0)
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
            else
            {
                int err = SSL_get_error(ssl.ssl, r);

                if (err == SSL_ERROR_WANT_READ)
                    pipeline->queueTlsConnecting(conn);
            }

            while (BIO_pending(ssl.wbio) > 0)
            {
                std::pair<std::array<char, BUFFER_SIZE>, int> chunk;
                int bytes = BIO_read(ssl.wbio, chunk.first.data(), BUFFER_SIZE);

                if (bytes > 0)
                {
                    chunk.second = bytes;
                    conn.writeQueue.push_back(std::move(chunk));
                }
            }

            if (!conn.writeQueue.empty() && !conn.isWritingClient)
            {
                conn.isWritingClient = true;

                pipeline->queueWriteClient(conn);
            }

            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_TLS_CONNECTING;
            break;
        }

        case Gen::STATE_READ_CLIENT:
        {
            conn.isReadingClient = false;

            if (res == 0)
            {
                Utils::Uring::closeConn(thread, conn);
                io_uring_submit(ring);
                break;
            }

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
                else
                {
                    pipeline->queueReadClient(conn);
                    io_uring_submit(ring);

                    break;
                }
            }

            if (conn.resolverFd == -1)
            {
                int resolverFd = Proxy::createResolverSocket();
                if (resolverFd == -1)
                {
                    conn.backendIsUnreachable = true;

                    pipeline->write502Page(conn);

                    if (!conn.isWritingClient)
                    {
                        conn.isWritingClient = true;
                        pipeline->queueWriteClient(conn);
                    }
                    io_uring_submit(ring);

                    break;
                }

                conn.resolverFd = resolverFd;

                pipeline->queueConnectResolver(conn);
                io_uring_submit(ring);
                conn.lastOpType = Gen::STATE_READ_CLIENT;
                break;
            }

            pipeline->queueWriteOrigin(conn);
            io_uring_submit(ring);
            conn.lastOpType = Gen::STATE_READ_CLIENT;
            break;
        }

        case Gen::STATE_WRITE_CLIENT:
        {
            if (!conn.writeQueue.empty())
            {
                if (res > 0)
                    conn.writeOffset += res;

                if (conn.writeOffset >= conn.writeQueue.front().second)
                {
                    conn.writeQueue.pop_front();
                    conn.writeOffset = 0;
                }
            }

            if (!conn.writeQueue.empty())
            {
                conn.isWritingClient = true;

                pipeline->queueWriteClient(conn);
                io_uring_submit(ring);
                break;
            }

            conn.isWritingClient = false;
            conn.writeOffset = 0;

            pipeline->queueReadClient(conn);
            io_uring_submit(ring);
            conn.lastOpType = Gen::STATE_WRITE_CLIENT;
            break;
        }

        // ===========================================
        //                ORIGIN
        // ===========================================
        case Gen::STATE_ORIGIN_CONNECTING:
        {
            pipeline->queueReadOrigin(conn);
            pipeline->queueWriteOrigin(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_ORIGIN_CONNECTING;
            break;
        }

        case Gen::STATE_WRITE_ORIGIN:
        {
            conn.lastOpType = Gen::STATE_WRITE_ORIGIN;
            break;
        }

        case Gen::STATE_READ_ORIGIN:
        {
            conn.isReadingOrigin = false;

            if (res == 0)
            {
                Utils::Uring::closeConn(thread, Gen::activeThreads[thread].connections[conn.peerFd]);
                io_uring_submit(ring);
                break;
            }

            if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
            {
                auto &ssl = Gen::activeThreads[thread].ssl[conn.fd];

                int r = SSL_write(ssl.ssl, conn.out_plain_buffer, res);
                (void)r;

                while (BIO_pending(ssl.wbio) > 0)
                {
                    std::pair<std::array<char, BUFFER_SIZE>, int> chunk;
                    int bytes = BIO_read(ssl.wbio, chunk.first.data(), BUFFER_SIZE);
                    chunk.second = bytes;

                    conn.writeQueue.push_back(std::move(chunk));
                }
            }
            else
            {
                std::pair<std::array<char, BUFFER_SIZE>, int> chunk;
                memcpy(chunk.first.data(), conn.out_plain_buffer, res);
                chunk.second = res;
                conn.writeQueue.push_back(std::move(chunk));
            }

            if (!conn.writeQueue.empty() && !conn.isWritingClient)
            {
                conn.isWritingClient = true;

                pipeline->queueWriteClient(conn);
            }

            pipeline->queueReadOrigin(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_READ_ORIGIN;
            break;
        }

        // ===========================================
        //                RESOLVER
        // ===========================================
        case Gen::STATE_CONNECT_RESOLVER:
        {
            conn.host = Utils::Http::getHost(Gen::activeThreads[thread].ssl[conn.fd].handshakeDone ? conn.in_plain_buffer : conn.in_raw_buffer, res);
            
            conn.resolverPacket[0] = 0x12;
            conn.resolverPacket[1] = 0x34;
            conn.resolverPacket[2] = 0x01;
            conn.resolverPacket[3] = 0x00;
            conn.resolverPacket[5] = 1;

            char *qname = &conn.resolverPacket[12];
            DNSClient::formatName(qname, conn.host);
            int qlen = strlen((char *)qname) + 1;
            conn.resolverPacket[12 + qlen + 1] = 1;
            conn.resolverPacket[12 + qlen + 3] = 1;

            conn.out_len = 12 + qlen + 4;

            pipeline->queueWriteResolver(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_CONNECT_RESOLVER;

            break;
        }

        case Gen::STATE_WRITE_RESOLVER:
        {
            pipeline->queueReadResolver(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_WRITE_RESOLVER;

            break;
        }

        case Gen::STATE_READ_RESOLVER:
        {
            char qname[256];
            DNSClient::formatName(qname, conn.host);
            int qlen = strlen((char *)qname) + 1;

            std::vector<std::string> ips;
            int count = ntohs(*(uint16_t *)&conn.in_raw_buffer[6]);
            char *p = &conn.in_raw_buffer[12 + qlen + 4];

            for (int i = 0; i < count; i++)
            {
                p += 2;
                uint16_t type = ntohs(*(uint16_t *)p);
                p += 8;
                uint16_t len = ntohs(*(uint16_t *)p);
                p += 2;

                if (type == 1)
                {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
                    ips.push_back(std::string(ip_str));
                }
                p += len;
            }

            if (conn.peerFd == -1)
            {
                std::string ip = DNSClient::getRandomIP(ips);

                sockaddr_in originAddr{};
                int peerFd = -1;

                    peerFd = Proxy::createOriginSocket((char *)"13.140.157.112", 80, originAddr);

                if (peerFd == -1)
                {
                    conn.backendIsUnreachable = true;

                    pipeline->write502Page(conn);

                    if (!conn.isWritingClient)
                    {
                        conn.isWritingClient = true;
                        pipeline->queueWriteClient(conn);
                    }
                    io_uring_submit(ring);

                    break;
                }

                Gen::Connection peerConn{};
                peerConn.fd = peerFd;
                peerConn.peerFd = conn.fd;
                peerConn.type = Gen::TYPE_ORIGIN;
                peerConn.originAddr = originAddr;
                conn.peerFd = peerFd;

                Gen::activeThreads[thread].connections.emplace(peerFd, std::move(peerConn));

                pipeline->queueConnectOrigin(Gen::activeThreads[thread].connections.at(peerFd));
                io_uring_submit(ring);

                conn.lastOpType = Gen::STATE_READ_RESOLVER;
                break;
            }

            pipeline->queueWriteOrigin(conn);
            io_uring_submit(ring);

            conn.lastOpType = Gen::STATE_READ_RESOLVER;

            break;
        }
        }
    }
}

void Core::memoryWorker(int thread)
{
    while (true)
    {
        volatile unsigned long long val = 0;
        for (int i = 0; i < 5000000; i++)
        {
            val += i * i;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}