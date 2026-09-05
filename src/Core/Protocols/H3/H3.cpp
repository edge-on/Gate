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
        std::cout << "WAKE UP" << std::endl;
        wakeup(res);
        return 0;
    }

    switch (opType)
    {
    case ::H3::Gen::H3_STATE_READ_CLIENT:
    {
        std::cout << "I RECV " << res << " BYTES" << std::endl;

        if (!hasMore)
        {
            pipeline->queueReadClient();
            io_uring_submit(ring);
        }

        if (res <= 0)
            break;

        int bufId = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        int groupId = ::H3::Gen::localUdpConfig.bufGroup;
        char *raw = pipeline->pool->getBufferAddress(groupId, bufId);

        struct msghdr *msgHdr = &::H3::Gen::localUdpConfig.msgHdr;

        struct io_uring_recvmsg_out *hdr = io_uring_recvmsg_validate(raw, res, msgHdr);
        if (!hdr)
            break;

        uint8_t *quicPayload = reinterpret_cast<uint8_t *>(io_uring_recvmsg_payload(hdr, msgHdr));
        size_t quicPayloadLen = io_uring_recvmsg_payload_length(hdr, res, msgHdr);

        uint32_t version = 0;
        uint8_t type = 0;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scidLen = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcidLen = sizeof(dcid);

        uint8_t token[256];
        size_t tokenLen = sizeof(token);

        int rc = quiche_header_info(quicPayload, quicPayloadLen, 18,
                                    &version, &type,
                                    scid, &scidLen,
                                    dcid, &dcidLen,
                                    token, &tokenLen);

        bool isLongHeader = (type != ::H3::Gen::quichePktType::QUICHE_PACKET_TYPE_SHORT);

        struct sockaddr *peerAddr = reinterpret_cast<struct sockaddr *>(io_uring_recvmsg_name(hdr));
        socklen_t peerLen = hdr->namelen;

        if (peerAddr->sa_family != AF_INET)
            break;

        struct sockaddr_in localAddr{};
        socklen_t localAddrLen = sizeof(localAddr);
        if (getsockname(Gen::activeThreads[thread].udpFd, reinterpret_cast<struct sockaddr *>(&localAddr), &localAddrLen) != 0)
            break;

        if (isLongHeader && !quiche_version_is_supported(version))
        {
            ::H3::Gen::ConnectionlessH3Context h3ctx;

            ssize_t writtenLen = quiche_negotiate_version(
                scid, scidLen,
                dcid, dcidLen,
                h3ctx.out, sizeof(h3ctx.out));

            if (writtenLen < 0)
                break;

            h3ctx.iov.iov_base = h3ctx.out;
            h3ctx.iov.iov_len = writtenLen;

            h3ctx.msg.msg_name = peerAddr;
            h3ctx.msg.msg_namelen = peerLen;
            h3ctx.msg.msg_iov = &h3ctx.iov;
            h3ctx.msg.msg_iovlen = 1;

            Gen::activeThreads[thread].connectionlessh3ctx.push(std::move(h3ctx));

            pipeline->queueWriteClientCtx();
            io_uring_submit(ring);

            break;
        }

        std::cout << "here works" << std::endl;

        std::string fkey(reinterpret_cast<char *>(dcid), dcidLen);

        bool isExist = false;

        auto mconn = Gen::activeThreads[thread].h3connections.find(fkey);
        if (mconn != Gen::activeThreads[thread].h3connections.end())
            isExist = true;

        if (hdr->namelen < sizeof(struct sockaddr_in))
            break;

        quiche_conn *quicConn;

        if (rc == 0 && type == ::H3::Gen::quichePktType::QUICHE_PACKET_TYPE_INITIAL)
        {
            if (!isExist)
            {
                std::array<uint8_t, 18> id;
                generateDcid(id);

                std::string key(reinterpret_cast<char *>(id.data()), id.size());

                quicConn = quiche_accept(
                    id.data(), id.size(),
                    dcid, dcidLen,
                    reinterpret_cast<struct sockaddr *>(&localAddr), localAddrLen,
                    peerAddr, peerLen,
                    conf);

                if (!quicConn)
                    break;

                SSL *ssl = (SSL *)quiche_conn_get_ssl(quicConn);

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
        }

        bool isIngress = Gen::activeThreads[thread].h3connections[fkey].dcidType == ::H3::Gen::INGRESS;

        auto &conn =
            isIngress
                ? Gen::activeThreads[thread].h3connections[Gen::activeThreads[thread].h3connections[fkey].peerDcid]
                : Gen::activeThreads[thread].h3connections[fkey];

        std::pair<std::array<char, DATAGRAM_SIZE>, int> chunk;
        memcpy(chunk.first.data(), quicPayload, quicPayloadLen);
        chunk.second = res;

        conn.readQueue.push_back(std::move(chunk));

        quiche_recv_info info = {
            .from = peerAddr,
            .from_len = peerLen,
            .to = reinterpret_cast<struct sockaddr *>(&localAddr),
            .to_len = localAddrLen,
        };

        ssize_t recvLen = quiche_conn_recv(conn.conn, quicPayload, quicPayloadLen, &info);

        std::cout << "Recv len: " << recvLen << std::endl;

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
                    std::cout << "QUICHE_H3_EVENT_HEADERS" << std::endl;

                    int rc = quiche_h3_event_for_each_header(ev, forEachHeaderCallback, nullptr);
                    if (rc < 0)
                        std::cout << "header parse error" << std::endl;

                    break;
                }
                case QUICHE_H3_EVENT_DATA:
                {
                    std::cout << "QUICHE_H3_EVENT_DATA" << std::endl;
                    break;
                }
                case QUICHE_H3_EVENT_FINISHED:
                {
                    std::cout << "QUICHE_H3_EVENT_FINISHED" << std::endl;
                    break;
                }
                }
                quiche_h3_event_free(ev);
            }
        }

        bool isWriting = false;
        while (true)
        {
            ::H3::Gen::Response res;

            ssize_t written = quiche_conn_send(conn.conn, res.out, sizeof(res.out), &res.sendInfo);

            if (written == QUICHE_ERR_DONE || written < 0)
            {
                break;
            }

            isWriting = true;

            conn.writeQueue.push_back(std::move(res));

            auto &back = conn.writeQueue.back();

            back.iov.iov_base = back.out;
            back.iov.iov_len = written;

            back.msg.msg_name = &back.sendInfo.to;

            struct sockaddr_in *saddr = reinterpret_cast<struct sockaddr_in *>(&back.sendInfo.to);
            std::cout << "Target IP: " << inet_ntoa(saddr->sin_addr) << " Port: " << ntohs(saddr->sin_port) << std::endl;

            struct sockaddr_in *paddr = reinterpret_cast<struct sockaddr_in *>(peerAddr);
            std::cout << "Peer IP: " << inet_ntoa(paddr->sin_addr) << " Port: " << ntohs(paddr->sin_port) << std::endl;

            back.msg.msg_namelen = back.sendInfo.to_len;
            back.msg.msg_iov = &back.iov;
            back.msg.msg_iovlen = 1;

            std::cout << written << std::endl;
        }

        std::cout << "size: " << conn.writeQueue.size() << std::endl;

        if (isWriting)
            pipeline->queueWriteClient(conn);

        io_uring_submit(ring);

        break;
    }

    case ::H3::Gen::H3_STATE_WRITE_CLIENT:
    {
        std::cout << "I write " << res << " bytes" << std::endl;

        auto dcidKeyPeering = Gen::activeThreads[thread].h3keys.find(dcidKey);
        if (dcidKeyPeering == Gen::activeThreads[thread].h3keys.end())
            std::cout << "DCID Key Peering doesnt exist!" << std::endl;

        std::string key = dcidKeyPeering->second.key;

        auto connIt = Gen::activeThreads[thread].h3connections.find(key);
        if (connIt == Gen::activeThreads[thread].h3connections.end())
            std::cout << "Connection doesnt exist with this key!" << std::endl;

        auto &conn = connIt->second;

        if (!conn.writeQueue.empty())
            conn.writeQueue.pop_front();

        if (!conn.writeQueue.empty())
            pipeline->queueWriteClient(conn);

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
    }

    return 0;
}

int Protocols::H3::wakeup(int res)
{
    auto items = Gen::activeThreads[thread].wakeup.drain();

    for (auto &item : items)
    {
        std::cout << "ITEM: " << item.key << std::endl;
    }
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

    quiche_h3_config *h3Config = quiche_h3_config_new();
    conn.h3 = quiche_h3_conn_new_with_transport(conn.conn, h3Config);
    quiche_h3_config_free(h3Config);

    conn.established = true;

    std::cout << "ESTABLISHED CONN, h3 layer ready" << std::endl;
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