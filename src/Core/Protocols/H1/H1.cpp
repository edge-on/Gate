#include "Core/Protocols/H1/H1.hpp"

Protocols::H1::H1(struct io_uring *ring, int thread, Pipeline::H1 *pipeline, SSL_CTX *ctx)
{
    this->ring = ring;
    this->thread = thread;
    this->pipeline = pipeline;
    this->ctx = ctx;
}

int Protocols::H1::run(struct io_uring_cqe *cqe)
{
    uint64_t data = (uint64_t)io_uring_cqe_get_data(cqe);
    int fd = (int)(data & 0xFFFFFFFF);
    int opType = (int)(data >> 32);

    int res = cqe->res;
    bool hasMore = cqe->flags & IORING_CQE_F_MORE;
    io_uring_cqe_seen(ring, cqe);

    if (res < 0)
    {
        if (opType == ::H1::Gen::H1_STATE_CONNECT_RESOLVER || opType == ::H1::Gen::H1_STATE_WRITE_RESOLVER || opType == ::H1::Gen::H1_STATE_READ_RESOLVER)
        {
            ::H1::Gen::H1Connection &conn = Gen::activeThreads[thread].h1connections[fd];
            close(conn.resolverFd);

            if (conn.missingSni)
                pipeline->writePage(conn, "sni");
            else
                pipeline->writePage(conn, "502");

            if (!conn.isWritingClient)
            {
                conn.isWritingClient = true;
                pipeline->queueWriteClient(conn);
            }
            io_uring_submit(ring);

            return Gen::CONTINUE;
        }

        if (opType == ::H1::Gen::H1_STATE_ORIGIN_CONNECTING)
        {
            ::H1::Gen::H1Connection &conn = Gen::activeThreads[thread].h1connections[fd];
            ::H1::Gen::H1Connection &originConn = Gen::activeThreads[thread].h1connections[conn.peerFd];
            pipeline->writePage(conn, "502");

            Utils::H1::Uring::closeConn(thread, originConn);
            conn.peerFd = -1;

            if (!conn.isWritingClient)
            {
                conn.isWritingClient = true;
                pipeline->queueWriteClient(conn);
            }
            io_uring_submit(ring);

            return Gen::CONTINUE;
        }

        auto it = Gen::activeThreads[thread].h1connections.find(fd);
        if (it != Gen::activeThreads[thread].h1connections.end())
        {
            auto peerIt = Gen::activeThreads[thread].h1connections.find(it->second.peerFd);
            if (peerIt != Gen::activeThreads[thread].h1connections.end())
            {
                Utils::H1::Uring::closeConn(thread, peerIt->second);
            }

            Utils::H1::Uring::closeConn(thread, it->second);
        }

        if (opType == ::H1::Gen::H1_STATE_ACCEPT_MULTISHOT)
        {
            pipeline->queueMultishotAccept(fd);
            io_uring_submit(ring);
        }

        return Gen::CONTINUE;
    }

    // ===========================================
    //                SOCKET
    // ===========================================
    if (opType == ::H1::Gen::H1_STATE_ACCEPT_MULTISHOT)
    {
        int clientFd = res;

        ::H1::Gen::H1Connection tempConn{};
        tempConn.fd = clientFd;
        tempConn.thread = thread;
        tempConn.type = Gen::TYPE_CLIENT;

        Gen::activeThreads[thread].generations[clientFd].connFd = clientFd;
        Gen::activeThreads[thread].generations[clientFd].gen += 1;

        tempConn.gen = Gen::activeThreads[thread].generations[clientFd].gen;

        Gen::activeThreads[thread].h1connections.erase(clientFd);
        Gen::activeThreads[thread].h1connections.emplace(clientFd, std::move(tempConn));

        auto &conn = Gen::activeThreads[thread].h1connections[clientFd];

        if (fd == Gen::activeThreads[thread].listeners[80])
        {
            conn.protocolState = ::H1::Gen::TCP_RAW;

            pipeline->queueReadClient(conn);
        }
        else if (fd == Gen::activeThreads[thread].listeners[443])
        {
            auto &ssl = Gen::activeThreads[thread].h1ssl[conn.fd];

            ssl.ssl = SSL_new(ctx);
            ssl.rbio = BIO_new(BIO_s_mem());
            ssl.wbio = BIO_new(BIO_s_mem());

            ssl.ioCtx.h1conn = &conn;
            ssl.ioCtx.protocol = Gen::H1;

            SSL_set_app_data(ssl.ssl, &ssl.ioCtx);

            conn.protocolState = ::H1::Gen::TCP_TLS;

            SSL_set_bio(ssl.ssl, ssl.rbio, ssl.wbio);
            SSL_set_accept_state(ssl.ssl);

            pipeline->queueTlsConnecting(conn);
        }

        if (!hasMore)
        {
            pipeline->queueMultishotAccept(fd);
        }

        if (conn.fd >= 0)
        {
            struct sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);

            if (getpeername(conn.fd, (struct sockaddr *)&peer_addr, &peer_len) == 0)
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peer_addr.sin_addr, ip_str, sizeof(ip_str));

                uint32_t providerAsn = Maxmind::DB::getVal(ip_str);

                if (Maxmind::DB::blockedAsns.find(providerAsn) != Maxmind::DB::blockedAsns.end())
                    conn.isBlocked = true;
            }
        }

        Gen::activeThreads[thread].activeConnections++;

        io_uring_submit(ring);
        conn.lastOpType = ::H1::Gen::H1_STATE_ACCEPT_MULTISHOT;

        return Gen::CONTINUE;
    }
    
    auto it = Gen::activeThreads[thread].h1connections.find(fd);
    if (it == Gen::activeThreads[thread].h1connections.end())
        return Gen::CONTINUE;

    ::H1::Gen::H1Connection &conn = it->second;

    if (conn.gen != Gen::activeThreads[thread].generations[conn.fd].gen)
        return Gen::CONTINUE;

    switch (opType)
    {
    // ===========================================
    //                CLIENT
    // ===========================================
    case ::H1::Gen::H1_STATE_TLS_CONNECTING:
    {
        auto &sslDbg = Gen::activeThreads[thread].h1ssl[conn.fd];
        conn.isReadingClient = false;

        if (res == 0)
        {
            Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
            io_uring_submit(ring);
            break;
        }

        auto &ssl = Gen::activeThreads[thread].h1ssl[conn.fd];

        int written = BIO_write(ssl.rbio, conn.in_raw_buffer, res);
        int r = SSL_accept(ssl.ssl);
        if (r > 0)
        {
            ssl.handshakeDone = true;

            const unsigned char *alpn_proto;
            unsigned int alpn_len;
            SSL_get0_alpn_selected(ssl.ssl, &alpn_proto, &alpn_len);
        }
        else
        {
            int err = SSL_get_error(ssl.ssl, r);

            if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL || err == SSL_ERROR_ZERO_RETURN)
            {
                Utils::H1::Uring::closeConn(thread, conn);
                io_uring_submit(ring);
                return Gen::CONTINUE;
            }

            if (err == SSL_ERROR_PENDING_CERTIFICATE)
            {
                pipeline->queueTlsConnecting(conn);
                io_uring_submit(ring);
                break;
            }

            if (err == SSL_ERROR_WANT_READ)
                pipeline->queueTlsConnecting(conn);
            else
                Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
        }

        if (!ssl.wbio || !ssl.rbio || !ssl.ssl)
        {
            Utils::H1::Uring::closeConn(thread, conn);
            io_uring_submit(ring);
            return Gen::CONTINUE;
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

        while (true && ssl.handshakeDone)
        {
            std::pair<std::array<char, BUFFER_SIZE>, int> chunk;

            int bytes = SSL_read(ssl.ssl, chunk.first.data(), BUFFER_SIZE);

            if (bytes > 0)
            {
                if (conn.isBlocked ||
                    Security::Headers::validateReq(chunk.first.data(), bytes) == Security::Headers::RequestStatus::BLOCKED)
                {
                    pipeline->writePage(conn, "403");

                    if (!conn.isWritingClient)
                    {
                        conn.isWritingClient = true;
                        pipeline->queueWriteClient(conn);
                    }

                    io_uring_submit(ring);
                    break;
                }

                if (conn.resolverFd == -1 && conn.host.empty())
                {
                    std::string host = Utils::Http::getHost(chunk.first.data(), bytes);
                    if (host != "undefined" && !host.empty())
                        conn.host = host;
                }

                chunk.second = bytes;
                conn.writeOriginQueue.push_back(std::move(chunk));
            }
            else
            {
                int err = SSL_get_error(ssl.ssl, bytes);
                if (err == SSL_ERROR_WANT_READ)
                {
                    pipeline->queueReadClient(conn);
                }
                else
                {
                    Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
                }

                break;
            }
        }

        if (conn.writeOriginQueue.size() > 0)
        {
            if (conn.resolverFd == -1)
            {
                int resolverFd = Proxy::createResolverSocket();
                if (resolverFd == -1)
                {
                    conn.backendIsUnreachable = true;

                    pipeline->writePage(conn, "502");

                    if (!conn.isWritingClient)
                    {
                        conn.isWritingClient = true;
                        pipeline->queueWriteClient(conn);
                    }
                    io_uring_submit(ring);

                    break;
                }

                conn.resolverFd = resolverFd;
                conn.out_len = res;

                pipeline->queueConnectResolver(conn, Main::resolverIp);
                io_uring_submit(ring);
                conn.lastOpType = ::H1::Gen::H1_STATE_TLS_CONNECTING;
                break;
            }

            if (!conn.isWritingOrigin && conn.writeOriginQueue.size() > 0)
            {
                conn.isWritingOrigin = true;
                pipeline->queueWriteOrigin(conn);
            }

            io_uring_submit(ring);
            conn.lastOpType = ::H1::Gen::H1_STATE_TLS_CONNECTING;
            break;
        }

        if (ssl.handshakeDone)
            pipeline->queueReadClient(conn);

        io_uring_submit(ring);

        conn.lastOpType = ::H1::Gen::H1_STATE_TLS_CONNECTING;
        break;
    }

    case ::H1::Gen::H1_STATE_READ_CLIENT:
    {
        conn.isReadingClient = false;

        if (conn.zone)
            conn.zone->inbound.fetch_add(res, std::memory_order_relaxed);

        if (res == 0)
        {
            Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
            io_uring_submit(ring);
            break;
        }

        conn.in_len = res;

        memset(conn.in_plain_buffer, 0, BUFFER_SIZE);

        // TCP TLS
        if (Gen::activeThreads[thread].h1ssl[conn.fd].handshakeDone)
        {
            auto &ssl = Gen::activeThreads[thread].h1ssl[conn.fd];
            int q = BIO_write(ssl.rbio, conn.in_raw_buffer, res);

            while (true)
            {
                std::pair<std::array<char, BUFFER_SIZE>, int> chunk;

                int bytes = SSL_read(ssl.ssl, chunk.first.data(), BUFFER_SIZE);
                if (bytes > 0)
                {
                    if (conn.isBlocked ||
                        Security::Headers::validateReq(chunk.first.data(), bytes) == Security::Headers::RequestStatus::BLOCKED)
                    {
                        pipeline->writePage(conn, "403");

                        if (!conn.isWritingClient)
                        {
                            conn.isWritingClient = true;
                            pipeline->queueWriteClient(conn);
                        }

                        io_uring_submit(ring);
                        break;
                    }

                    if (conn.resolverFd == -1 && conn.host.empty())
                    {
                        std::string host = Utils::Http::getHost(chunk.first.data(), bytes);
                        if (host != "undefined" && !host.empty())
                            conn.host = host;
                    }

                    chunk.second = bytes;
                    conn.writeOriginQueue.push_back(std::move(chunk));
                }
                else
                {
                    int err = SSL_get_error(ssl.ssl, bytes);
                    if (err == SSL_ERROR_WANT_READ)
                    {
                        pipeline->queueReadClient(conn);
                    }
                    else
                    {
                        Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
                    }

                    break;
                }
            }

            if (!conn.writeOriginQueue.size() > 0)
            {
                pipeline->queueReadClient(conn);
                io_uring_submit(ring);

                break;
            }
        }

        // I will not aplly write origin queue architecture to port 80 fd's, because of we are not send origin responses to client
        // At least for now

        // If request from port 80
        if (!Gen::activeThreads[thread].h1ssl[conn.fd].handshakeDone)
        {
            std::string host = Utils::Http::getHost(conn.in_raw_buffer, res);
            std::string permanentlyMoved = "HTTP/1.1 301 Moved Permanently\r\n"
                                           "Location: https://" +
                                           host + "/\r\n"
                                                  "Content-Length: 0\r\n"
                                                  "Connection: close\r\n\r\n";

            if (permanentlyMoved.size() <= BUFFER_SIZE)
            {
                std::pair<std::array<char, BUFFER_SIZE>, int> chunk;

                memcpy(chunk.first.data(), permanentlyMoved.data(), permanentlyMoved.size());
                chunk.second = static_cast<int>(permanentlyMoved.size());

                conn.writeQueue.push_back(std::move(chunk));
                conn.pendingClose = true;

                pipeline->queueWriteClient(conn);
                io_uring_submit(ring);
            }
            else
            {
                std::cerr << "Response size exceeds BUFFER_SIZE!" << std::endl;
            }

            break;
        }

        memset(conn.in_raw_buffer, 0, BUFFER_SIZE);

        if (conn.resolverFd == -1)
        {
            int resolverFd = Proxy::createResolverSocket();
            if (resolverFd == -1)
            {
                conn.backendIsUnreachable = true;

                pipeline->writePage(conn, "502");

                if (!conn.isWritingClient)
                {
                    conn.isWritingClient = true;
                    pipeline->queueWriteClient(conn);
                }
                io_uring_submit(ring);

                break;
            }

            conn.resolverFd = resolverFd;
            conn.out_len = res;

            pipeline->queueConnectResolver(conn, Main::resolverIp);
            io_uring_submit(ring);
            conn.lastOpType = ::H1::Gen::H1_STATE_READ_CLIENT;
            break;
        }

        if (!conn.isWritingOrigin && conn.writeOriginQueue.size() > 0)
        {
            conn.isWritingOrigin = true;
            pipeline->queueWriteOrigin(conn);
        }

        io_uring_submit(ring);
        conn.lastOpType = ::H1::Gen::H1_STATE_READ_CLIENT;
        break;
    }

    case ::H1::Gen::H1_STATE_WRITE_CLIENT:
    {
        if (conn.zone)
            conn.zone->outbound.fetch_add(res, std::memory_order_relaxed);

        if (!conn.writeQueue.empty())
        {
            if (res > 0)
            {
                conn.writeOffset += res;
            }

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

        if (conn.pendingClose)
        {
            Utils::H1::Uring::closeConnectionFull(thread, fd);
            io_uring_submit(ring);
            break;
        }

        pipeline->queueReadClient(conn);
        io_uring_submit(ring);
        conn.lastOpType = ::H1::Gen::H1_STATE_WRITE_CLIENT;
        break;
    }

    // ===========================================
    //                ORIGIN
    // ===========================================
    case ::H1::Gen::H1_STATE_ORIGIN_CONNECTING:
    {
        pipeline->queueReadOrigin(conn);

        if (!conn.isWritingOrigin && conn.writeOriginQueue.size() > 0)
        {
            conn.isWritingOrigin = true;
            pipeline->queueWriteOrigin(conn);
        }

        io_uring_submit(ring);

        conn.lastOpType = ::H1::Gen::H1_STATE_ORIGIN_CONNECTING;
        break;
    }

    case ::H1::Gen::H1_STATE_WRITE_ORIGIN:
    {
        if (conn.zone)
            conn.zone->outbound.fetch_add(res, std::memory_order_relaxed);

        if (!conn.writeOriginQueue.empty())
        {
            if (res > 0)
            {
                conn.writeOriginOffset += res;
            }

            if (conn.writeOriginOffset >= conn.writeOriginQueue.front().second)
            {
                conn.writeOriginQueue.pop_front();
                conn.writeOriginOffset = 0;
            }
        }

        if (!conn.writeOriginQueue.empty())
        {
            conn.isWritingOrigin = true;

            pipeline->queueWriteOrigin(conn);
            io_uring_submit(ring);

            conn.lastOpType = ::H1::Gen::H1_STATE_WRITE_ORIGIN;
            break;
        }

        conn.isWritingOrigin = false;
        conn.writeOriginOffset = 0;

        io_uring_submit(ring);

        conn.lastOpType = ::H1::Gen::H1_STATE_WRITE_ORIGIN;
        break;
    }

    case ::H1::Gen::H1_STATE_READ_ORIGIN:
    {
        if (conn.zone)
            conn.zone->inbound.fetch_add(res, std::memory_order_relaxed);

        conn.isReadingOrigin = false;

        if (res == 0)
        {
            if (conn.peerFd != -1)
            {
                auto originIt = Gen::activeThreads[thread].h1connections.find(conn.peerFd);
                if (originIt != Gen::activeThreads[thread].h1connections.end())
                    Utils::H1::Uring::closeConn(thread, originIt->second);
                conn.peerFd = -1;
            }

            if (!conn.writeQueue.empty())
            {
                conn.pendingClose = true;
                if (!conn.isWritingClient)
                {
                    conn.isWritingClient = true;
                    pipeline->queueWriteClient(conn);
                }
            }
            else
            {
                Utils::H1::Uring::closeConn(thread, conn);
            }

            io_uring_submit(ring);
            break;
        }

        if (res >= 12 && strncmp(conn.out_plain_buffer, "HTTP/1.", 7) == 0)
        {
            char *headerEnd = (char *)memmem(conn.out_plain_buffer, res, "\r\n\r\n", 4);
            if (headerEnd != NULL)
            {
                size_t headerBytes = headerEnd - conn.out_plain_buffer;
                if (Utils::Http::getHeader(conn.out_plain_buffer, headerBytes, "location:") != "undefined")
                {
                    const char *header = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
                        /*"Alt-Svc: h3=\":443\"; ma=2592000\r\n"*/;
                    size_t len = strlen(header);
                    size_t bodyBytes = res - headerBytes;

                    if (res + len <= BUFFER_SIZE)
                    {
                        memmove(headerEnd + len, headerEnd, bodyBytes);
                        memcpy(headerEnd, header, len);
                        res += len;
                    }
                }
            }
        }

        if (Gen::activeThreads[thread].h1ssl[conn.fd].handshakeDone)
        {
            auto &ssl = Gen::activeThreads[thread].h1ssl[conn.fd];

            int written = 0;
            while (written < res)
            {
                int r = SSL_write(ssl.ssl, conn.out_plain_buffer + written, res - written);
                if (r <= 0)
                {
                    int err = SSL_get_error(ssl.ssl, r);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                        break;
                    continue;
                }
                written += r;
            }

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

        conn.lastOpType = ::H1::Gen::H1_STATE_READ_ORIGIN;
        break;
    }

    // ===========================================
    //                RESOLVER
    // ===========================================
    case ::H1::Gen::H1_STATE_CONNECT_RESOLVER:
    {
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

        conn.lastOpType = ::H1::Gen::H1_STATE_CONNECT_RESOLVER;

        break;
    }

    case ::H1::Gen::H1_STATE_WRITE_RESOLVER:
    {
        if (conn.zone)
            conn.zone->inbound.fetch_add(res, std::memory_order_relaxed);

        pipeline->queueReadResolver(conn);
        io_uring_submit(ring);

        conn.lastOpType = ::H1::Gen::H1_STATE_WRITE_RESOLVER;

        break;
    }

    case ::H1::Gen::H1_STATE_READ_RESOLVER:
    {
        if (res == 0 && conn.resolverFd != -1)
            close(conn.resolverFd);

        char qname[256];
        DNSClient::formatName(qname, conn.host);
        int qlen = strlen((char *)qname) + 1;

        char *buf_start = conn.in_raw_buffer;
        char *buf_end = conn.in_raw_buffer + res;

        auto fail_resolver = [&]()
        {
            conn.backendIsUnreachable = true;
            pipeline->writePage(conn, "502");
            if (!conn.isWritingClient)
            {
                conn.isWritingClient = true;
                pipeline->queueWriteClient(conn);
            }
            io_uring_submit(ring);
        };

        if (res < 12 + qlen + 4)
        {
            fail_resolver();
            break;
        }

        std::vector<std::string> ips;
        int count = ntohs(*(uint16_t *)&conn.in_raw_buffer[6]);
        char *p = &conn.in_raw_buffer[12 + qlen + 4];

        auto remaining = [&](char *ptr) -> long
        {
            return buf_end - ptr;
        };

        auto skip_name = [&](char *&ptr) -> bool
        {
            while (ptr < buf_end)
            {
                uint8_t label_len = (uint8_t)*ptr;
                if ((label_len & 0xC0) == 0xC0)
                {
                    ptr += 2;
                    return ptr <= buf_end;
                }
                else if (label_len == 0)
                {
                    ptr += 1;
                    return ptr <= buf_end;
                }
                else
                {
                    ptr += 1 + label_len;
                    if (ptr > buf_end)
                        return false;
                }
            }
            return false;
        };

        bool parse_ok = true;

        for (int i = 0; i < count; i++)
        {
            if (!skip_name(p))
            {
                parse_ok = false;
                break;
            }

            if (remaining(p) < 10)
            {
                parse_ok = false;
                break;
            }

            uint16_t type = ntohs(*(uint16_t *)p);
            p += 8;

            uint16_t len = ntohs(*(uint16_t *)p);
            p += 2;

            if (remaining(p) < (long)len)
            {
                parse_ok = false;
                break;
            }

            if (type == 1 && len == 4) // A record
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
                ips.push_back(std::string(ip_str));
            }

            p += len;
        }

        if (!parse_ok)
        {
            fail_resolver();
            break;
        }

        if (conn.zone)
        {
            conn.zone->inbound.fetch_add(res, std::memory_order_relaxed);
            conn.zone->dnsQueries.fetch_add(1, std::memory_order_relaxed);
        }

        if (conn.peerFd == -1)
        {
            std::string ip = DNSClient::getRandomIP(ips);

            sockaddr_in originAddr{};
            int peerFd = -1;

            if (!ip.empty())
                peerFd = Proxy::createOriginSocket((char *)ip.data(), 80, originAddr);

            if (peerFd == -1)
            {
                fail_resolver();
                break;
            }

            ::H1::Gen::H1Connection peerConn{};
            peerConn.fd = peerFd;
            peerConn.peerFd = conn.fd;
            peerConn.type = Gen::TYPE_ORIGIN;
            peerConn.originAddr = originAddr;
            conn.peerFd = peerFd;

            if (conn.resolverFd != -1)
            {
                close(conn.resolverFd);
                conn.resolverFd = -1;
            }

            Gen::activeThreads[thread].h1connections.emplace(peerFd, std::move(peerConn));

            pipeline->queueConnectOrigin(Gen::activeThreads[thread].h1connections.at(peerFd));
            io_uring_submit(ring);

            conn.lastOpType = ::H1::Gen::H1_STATE_READ_RESOLVER;
            break;
        }

        if (!conn.isWritingOrigin && conn.writeOriginQueue.size() > 0)
        {
            conn.isWritingOrigin = true;
            pipeline->queueWriteOrigin(conn);
        }

        io_uring_submit(ring);
        conn.lastOpType = ::H1::Gen::H1_STATE_READ_RESOLVER;
        break;
    }
    }

    return 0;
}

int Protocols::H1::wakeup(int res)
{
    auto items = Gen::activeThreads[thread].wakeup.drain();

    for (auto &item : items)
    {
        if (!item.success)
            continue;

        auto it = Gen::activeThreads[thread].h1connections.find(item.fd);
        if (it == Gen::activeThreads[thread].h1connections.end())
            continue;

        auto &conn = it->second;

        conn.lastOpType = ::H1::Gen::H1_STATE_TLS_CONNECTING;

        auto &ssl = Gen::activeThreads[thread].h1ssl[conn.fd];
        int r = SSL_accept(ssl.ssl);
        if (r > 0)
        {
            ssl.handshakeDone = true;

            const unsigned char *alpn_proto;
            unsigned int alpn_len;
            SSL_get0_alpn_selected(ssl.ssl, &alpn_proto, &alpn_len);
        }
        else
        {
            int err = SSL_get_error(ssl.ssl, r);

            if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL || err == SSL_ERROR_ZERO_RETURN)
            {
                Utils::H1::Uring::closeConn(thread, conn);
                io_uring_submit(ring);
                continue;
            }

            if (err == SSL_ERROR_PENDING_CERTIFICATE)
            {
                pipeline->queueTlsConnecting(conn);
                continue;
            }

            if (err == SSL_ERROR_WANT_READ)
                pipeline->queueTlsConnecting(conn);
            else
                Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
        }

        if (!ssl.wbio || !ssl.rbio || !ssl.ssl)
        {
            Utils::H1::Uring::closeConn(thread, conn);
            io_uring_submit(ring);
            continue;
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

        while (true && ssl.handshakeDone)
        {
            std::pair<std::array<char, BUFFER_SIZE>, int> chunk;

            int bytes = SSL_read(ssl.ssl, chunk.first.data(), BUFFER_SIZE);

            if (bytes > 0)
            {
                if (conn.isBlocked ||
                    Security::Headers::validateReq(chunk.first.data(), bytes) == Security::Headers::RequestStatus::BLOCKED)
                {
                    pipeline->writePage(conn, "403");

                    if (!conn.isWritingClient)
                    {
                        conn.isWritingClient = true;
                        pipeline->queueWriteClient(conn);
                    }

                    io_uring_submit(ring);
                    break;
                }

                if (conn.resolverFd == -1 && conn.host.empty())
                {
                    std::string host = Utils::Http::getHost(chunk.first.data(), bytes);
                    if (host != "undefined" && !host.empty())
                        conn.host = host;
                }

                chunk.second = bytes;
                conn.writeOriginQueue.push_back(std::move(chunk));
            }
            else
            {
                int err = SSL_get_error(ssl.ssl, bytes);
                if (err == SSL_ERROR_WANT_READ)
                {
                    pipeline->queueReadClient(conn);
                }
                else
                {
                    Utils::H1::Uring::closeConnectionFull(thread, conn.fd);
                }

                break;
            }
        }

        if (conn.writeOriginQueue.size() > 0 && ssl.handshakeDone)
        {
            if (conn.resolverFd == -1)
            {
                int resolverFd = Proxy::createResolverSocket();
                if (resolverFd == -1)
                {
                    conn.backendIsUnreachable = true;

                    pipeline->writePage(conn, "502");

                    if (!conn.isWritingClient)
                    {
                        conn.isWritingClient = true;
                        pipeline->queueWriteClient(conn);
                    }
                    io_uring_submit(ring);

                    continue;
                }

                conn.resolverFd = resolverFd;
                conn.out_len = res;

                pipeline->queueConnectResolver(conn, Main::resolverIp);
                io_uring_submit(ring);
                conn.lastOpType = ::H1::Gen::H1_STATE_TLS_CONNECTING;
                continue;
            }

            if (!conn.isWritingOrigin && conn.writeOriginQueue.size() > 0)
            {
                conn.isWritingOrigin = true;
                pipeline->queueWriteOrigin(conn);
            }

            io_uring_submit(ring);
            conn.lastOpType = ::H1::Gen::H1_STATE_TLS_CONNECTING;
            continue;
        }
        else if (ssl.handshakeDone)
        {
            pipeline->queueReadClient(conn);
        }
    }

    io_uring_submit(ring);
    return Gen::CONTINUE;
}