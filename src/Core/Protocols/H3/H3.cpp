#include "Core/Protocols/H3/H3.hpp"

Protocols::H3::H3(struct io_uring *ring, int thread, Pipeline::H3 *pipeline, struct quiche_config *conf, SSL_CTX *ctx)
{
    this->ring = ring;
    this->conf = conf;

    this->thread = thread;

    this->pipeline = pipeline;

    this->ctx = ctx;
}

int Protocols::H3::run(struct io_uring_cqe *cqe)
{
    uint64_t data = (uint64_t)io_uring_cqe_get_data(cqe);
    int dcidKey = (int)(data & 0xFFFFFFFF);
    int opType = (int)(data >> 32);

    int res = cqe->res;
    bool hasMore = cqe->flags & IORING_CQE_F_MORE;

    if (res < 0)
    {
        return Gen::CONTINUE;
    }

    if (opType == Gen::STATE_TLS_WAKEUP)
    {
        wakeup(res);
        return 0;
    }

    switch (opType)
    {
    case ::H3::Gen::H3_STATE_READ_CLIENT:
    {
        bool isExist = false;

        if (!hasMore)
        {
            fprintf(stderr, "[thread %d] multishot ended, re-arming\n", thread);
            pipeline->queueReadClient();
        }

        if (res <= 0)
        {
            io_uring_submit(ring);
            break;
        }

        int bufId = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        int groupId = ::H3::Gen::localUdpConfig.bufGroup;
        char *raw = pipeline->pool->getBufferAddress(groupId, bufId);

        struct msghdr *msgHdr = &::H3::Gen::localUdpConfig.msgHdr;

        struct io_uring_recvmsg_out *hdr = io_uring_recvmsg_validate(raw, res, msgHdr);
        if (!hdr)
        {
            io_uring_submit(ring);
            break;
        }

        uint8_t *quicPayload = reinterpret_cast<uint8_t *>(io_uring_recvmsg_payload(hdr, msgHdr));
        size_t quicPayloadLen = io_uring_recvmsg_payload_length(hdr, res, msgHdr);

        ::H3::Gen::HdrInfoCtx infoCtx;

        int rc = quiche_header_info(quicPayload, quicPayloadLen, 18,
                                    &infoCtx.version, &infoCtx.type,
                                    infoCtx.scid, &infoCtx.scidLen,
                                    infoCtx.dcid, &infoCtx.dcidLen,
                                    infoCtx.token, &infoCtx.tokenLen);

        struct sockaddr *peerAddr = reinterpret_cast<struct sockaddr *>(io_uring_recvmsg_name(hdr));
        socklen_t peerLen = hdr->namelen;
        if (peerAddr->sa_family != AF_INET)
        {
            io_uring_submit(ring);
            break;
        }

        struct sockaddr_in localAddr{};
        socklen_t localAddrLen = sizeof(localAddr);
        if (getsockname(Gen::activeThreads[thread].udpFd, reinterpret_cast<struct sockaddr *>(&localAddr), &localAddrLen) != 0)
        {
            io_uring_submit(ring);
            break;
        }

        if (versionMismatch(infoCtx, peerAddr, peerLen))
            break;

        std::string fkey(reinterpret_cast<char *>(infoCtx.dcid), infoCtx.dcidLen);

        auto mconn = Gen::activeThreads[thread].h3connections.find(fkey);
        if (mconn != Gen::activeThreads[thread].h3connections.end())
            isExist = true;

        if (hdr->namelen < sizeof(struct sockaddr_in))
        {
            io_uring_submit(ring);
            break;
        }

        if (rc == 0)
        {
            switch (infoCtx.type)
            {
            case ::H3::Gen::QUICHE_PACKET_TYPE_INITIAL:
            {
                if (!isExist)
                {
                    std::array<uint8_t, 18> id;
                    generateDcid(id);

                    std::string key(reinterpret_cast<char *>(id.data()), id.size());

                    quiche_conn *quicConn = quiche_accept(
                        id.data(), id.size(),
                        infoCtx.tokenLen > 0 ? infoCtx.dcid : nullptr,
                        infoCtx.tokenLen > 0 ? infoCtx.dcidLen : 0,
                        reinterpret_cast<struct sockaddr *>(&localAddr), localAddrLen,
                        peerAddr, peerLen,
                        conf);

                    SSL *ssl = (SSL *)quiche_conn_get_ssl(quicConn);
                    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

                    if (!quicConn)
                    {
                        io_uring_submit(ring);
                        break;
                    }

                    Gen::activeThreads[thread].h3ssl[key].dcid = id;
                    Gen::activeThreads[thread].h3ssl[key].ssl = ssl;

                    auto &tmpConn = Gen::activeThreads[thread].h3connections[key];
                    tmpConn.key = key;
                    tmpConn.peerDcid = fkey;
                    tmpConn.streamId = 0;
                    tmpConn.conn = quicConn;
                    tmpConn.dcidType = ::H3::Gen::ASSIGNED;
                    tmpConn.threadId = thread;

                    createKeyPeering(key);

                    Gen::activeThreads[thread].h3connections[fkey].dcidType = ::H3::Gen::INGRESS;
                    Gen::activeThreads[thread].h3connections[fkey].key = fkey;
                    Gen::activeThreads[thread].h3connections[fkey].peerDcid = key;
                    Gen::activeThreads[thread].h3connections[fkey].threadId = thread;

                    createKeyPeering(fkey);

                    Gen::activeThreads[thread].h3ssl[key].ioCtx.thread = thread;
                    Gen::activeThreads[thread].h3ssl[key].ioCtx.key = key;
                    Gen::activeThreads[thread].h3ssl[key].ioCtx.protocol = Gen::H3;

                    SSL_set_app_data(ssl, &Gen::activeThreads[thread].h3ssl[key].ioCtx);
                }

                break;
            }
            }
        }

        auto it = Gen::activeThreads[thread].h3connections.find(fkey);
        if (it == Gen::activeThreads[thread].h3connections.end())
        {
            io_uring_submit(ring);
            break;
        }

        bool isIngress = Gen::activeThreads[thread].h3connections[fkey].dcidType == ::H3::Gen::INGRESS;

        auto &conn =
            isIngress
                ? Gen::activeThreads[thread].h3connections[Gen::activeThreads[thread].h3connections[fkey].peerDcid]
                : Gen::activeThreads[thread].h3connections[fkey];

        quiche_recv_info info = {
            .from = peerAddr,
            .from_len = peerLen,
            .to = reinterpret_cast<struct sockaddr *>(&localAddr),
            .to_len = localAddrLen,
        };

        ssize_t recvLen = quiche_conn_recv(conn.conn, quicPayload, quicPayloadLen, &info);

        if (quiche_conn_is_established(conn.conn))
            establisheConnection(conn);

        if (conn.established)
        {
            quiche_h3_event *ev;
            int64_t streamId;

            while ((streamId = quiche_h3_conn_poll(conn.h3, conn.conn, &ev)) >= 0)
            {
                switch (quiche_h3_event_type(ev))
                {
                case QUICHE_H3_EVENT_HEADERS:
                {
                    ::H3::Gen::RecvIOCtx ioCtx;
                    int hrc = quiche_h3_event_for_each_header(ev, forEachHeaderCallback, &ioCtx);

                    std::string h1;
                    h1.append(ioCtx.method);
                    h1.append(" ");
                    h1.append(ioCtx.path);
                    h1.append(" HTTP/1.1\r\n");
                    h1.append("Host: ");
                    h1.append(ioCtx.host);
                    h1.append("\r\n");

                    for (auto header : ioCtx.headers)
                    {
                        h1.append(header);
                        h1.append("\r\n");
                    }

                    conn.readQueue.push_back(std::move(h1));

                    /*const char *body = "Hello, HTTP/3!";
                    std::string bodyLen = std::to_string(strlen(body));
                    quiche_h3_header headers[] = {
                        {.name = (uint8_t *)":status", .name_len = 7, .value = (uint8_t *)"200", .value_len = 3},
                        {.name = (uint8_t *)"content-length", .name_len = 14, .value = (uint8_t *)bodyLen.c_str(), .value_len = bodyLen.size()},
                        {.name = (uint8_t *)"content-type", .name_len = 12, .value = (uint8_t *)"text/plain", .value_len = 10},
                    };

                    quiche_h3_send_response(conn.h3, conn.conn, streamId, headers, 3, false);
                    quiche_h3_send_body(conn.h3, conn.conn, streamId, (uint8_t *)body, strlen(body), true);*/

                    break;
                }
                case QUICHE_H3_EVENT_DATA:
                    break;
                case QUICHE_H3_EVENT_FINISHED:
                    break;
                }
                quiche_h3_event_free(ev);
            }
        }

        if (!conn.readQueue.empty())
        {
            if (conn.resolverFd == -1)
            {
                std::cout << "Resolver fd is invalid" << std::endl;
                break;
            }

            if (conn.originFd == -1)
            {
                std::cout << "Origin fd is invalid" << std::endl;
                break;
            }

            break;
        }

        while (true)
        {
            ::H3::Gen::Response res;

            ssize_t written = quiche_conn_send(conn.conn, res.out, sizeof(res.out), &res.sendInfo);

            if (written == QUICHE_ERR_DONE || written < 0)
            {
                break;
            }

            conn.writeQueue.push_back(std::move(res));

            auto &back = conn.writeQueue.back();

            back.iov.iov_base = back.out;
            back.iov.iov_len = written;

            back.msg.msg_name = &back.sendInfo.to;

            back.msg.msg_namelen = back.sendInfo.to_len;
            back.msg.msg_iov = &back.iov;
            back.msg.msg_iovlen = 1;
        }

        if (!conn.writeInFlight)
        {
            conn.writeInFlight = true;
            pipeline->queueWriteClient(conn);
        }

        io_uring_submit(ring);

        break;
    }

    case ::H3::Gen::H3_STATE_WRITE_CLIENT:
    {
        auto dcidKeyPeering = Gen::activeThreads[thread].h3keys.find(dcidKey);
        if (dcidKeyPeering == Gen::activeThreads[thread].h3keys.end())
            break;

        std::string key = dcidKeyPeering->second.key;

        auto connIt = Gen::activeThreads[thread].h3connections.find(key);
        if (connIt == Gen::activeThreads[thread].h3connections.end())
            break;

        auto &conn = connIt->second;

        if (!conn.writeQueue.empty())
            conn.writeQueue.pop_front();

        if (!conn.writeQueue.empty())
            pipeline->queueWriteClient(conn);
        else
            conn.writeInFlight = false;

        io_uring_submit(ring);
        break;
    }

    case ::H3::Gen::H3_STATE_WRITE_CLIENT_CONNECTIONLESS:
    {
        if (!Gen::activeThreads[thread].connectionlessh3ctx.empty())
            Gen::activeThreads[thread].connectionlessh3ctx.pop();

        if (!Gen::activeThreads[thread].connectionlessh3ctx.empty())
            pipeline->queueWriteClientCtx();

        io_uring_submit(ring);

        break;
    }

    /* ============== RESOLVER ============== */
    case ::H3::Gen::H3_STATE_CONNECT_RESOLVER:
    {
        break;
    }

    case ::H3::Gen::H3_STATE_READ_RESOLVER:
    {
        break;
    }

    case ::H3::Gen::H3_STATE_WRITE_ORIGIN:
    {
        break;
    }
        /* ============== RESOLVER ============== */
    }

    return 0;
}

int Protocols::H3::wakeup(int res)
{
    auto items = Gen::activeThreads[thread].wakeup.drain();

    for (auto &item : items)
    {
    }

    return 0;
}

void Protocols::H3::generateDcid(std::array<uint8_t, 18> &out)
{
    if (RAND_bytes(out.data(), out.size()) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }
}

void Protocols::H3::establisheConnection(::H3::Gen::H3Connection &conn)
{
    if (conn.h3 != nullptr)
        return;

    std::string oldKey = conn.peerDcid;
    int oldPeeringKey = Gen::activeThreads[thread].h3connections[oldKey].keyPeering;

    quiche_h3_config *h3Config = quiche_h3_config_new();
    conn.h3 = quiche_h3_conn_new_with_transport(conn.conn, h3Config);
    quiche_h3_config_free(h3Config);

    conn.established = true;
}

uint32_t Protocols::H3::createKeyPeering(std::string key)
{
    uint32_t size = Gen::activeThreads[thread].h3keys.size();
    Gen::activeThreads[thread].h3keys[size].key = key;
    Gen::activeThreads[thread].h3connections[key].keyPeering = size;
    return size;
}

bool Protocols::H3::deleteKeyPeering(uint32_t keyPeering)
{
    Gen::activeThreads[thread].h3keys.erase(keyPeering);
    return true;
}

bool Protocols::H3::versionMismatch(::H3::Gen::HdrInfoCtx infoCtx, struct sockaddr *peerAddr, ssize_t peerLen)
{
    bool isLongHeader = (infoCtx.type != ::H3::Gen::quichePktType::QUICHE_PACKET_TYPE_SHORT);
    if (isLongHeader && !quiche_version_is_supported(infoCtx.version))
    {
        Gen::activeThreads[thread].connectionlessh3ctx.push(::H3::Gen::ConnectionlessH3Context{});
        auto &ctx = Gen::activeThreads[thread].connectionlessh3ctx.back();

        ssize_t writtenLen = quiche_negotiate_version(
            infoCtx.scid, infoCtx.scidLen,
            infoCtx.dcid, infoCtx.dcidLen,
            ctx.out, sizeof(ctx.out));

        if (writtenLen < 0)
        {
            Gen::activeThreads[thread].connectionlessh3ctx.pop();
            io_uring_submit(ring);
            return true;
        }

        memcpy(&ctx.peerAddrStorage, peerAddr, peerLen);

        ctx.iov.iov_base = ctx.out;
        ctx.iov.iov_len = writtenLen;

        ctx.msg.msg_name = &ctx.peerAddrStorage;
        ctx.msg.msg_namelen = peerLen;
        ctx.msg.msg_iov = &ctx.iov;
        ctx.msg.msg_iovlen = 1;

        pipeline->queueWriteClientCtx();
        io_uring_submit(ring);

        return true;
    }

    return false;
}

int Protocols::H3::forEachHeaderCallback(uint8_t *name, size_t nameLen, uint8_t *value, size_t valueLen, void *argp)
{
    auto *ioCtx = static_cast<::H3::Gen::RecvIOCtx *>(argp);

    std::string headerName(reinterpret_cast<char *>(name), nameLen);
    std::string headerValue(reinterpret_cast<char *>(value), valueLen);

    /*
    [METHOD VALUE] [PATH VALUE] HTTP/1.1
    Host: [AUTHORITY VALUE]
    for()
    {
        [HEADER NAME]: [HEADER VALUE]
    }
    */

    if (headerName == ":method")
    {
        ioCtx->method = headerValue.data(); // [METHOD VALUE]
        return 0;
    }

    if (headerName == ":path")
    {
        ioCtx->path = headerValue.data(); // [PATH VALUE]
        return 0;
    }

    if (headerName == ":authority")
    {
        ioCtx->host = headerValue.data(); // [AUTHORITY VALUE]
        return 0;
    }

    if (headerName == ":scheme")
        return 0;

    ioCtx->headers.push_back(headerName + ": " + headerValue);

    return 0;
}