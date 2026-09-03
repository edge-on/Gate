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
    int opType = (int)data;

    int res = cqe->res;
    bool hasMore = cqe->flags & IORING_CQE_F_MORE;
    io_uring_cqe_seen(ring, cqe);

    if (res < 0)
    {
        return Gen::CONTINUE;
    }

    switch (opType)
    {
    case ::H3::Gen::H3_STATE_READ_CLIENT:
    {
        if (res <= 0)
            break;

        int bufId = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        int groupId = ::H3::Gen::localUdpConfig.bufGroup;
        char *raw = pipeline->pool->getBufferAddress(groupId, bufId);

        struct msghdr *msgHdr = &::H3::Gen::localUdpConfig.msgHdr;

        struct io_uring_recvmsg_out *hdr = io_uring_recvmsg_validate(raw, res, msgHdr);
        if (!hdr)
        {
            return Gen::CONTINUE;
        }

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

        int rc = quiche_header_info(quicPayload, quicPayloadLen, LOCAL_CONN_ID_LEN,
                                    &version, &type,
                                    scid, &scidLen,
                                    dcid, &dcidLen,
                                    token, &tokenLen);

        for (auto c : dcid)
        {
            printf("%d", c);
            std::cout << " ";
        }

        std::cout << std::endl;

        /*
            TYPES
               0x01 = HEADER INITIAL
               0x02 = RETRY
               0x03 = HANDSHAKE
               0x04 = 0-RTT
        */
        if (rc == 0 && type == 0x01)
        {
            if (hdr->namelen < sizeof(struct sockaddr_in))
            {
                return Gen::CONTINUE;
            }

            struct sockaddr *peerAddr = reinterpret_cast<struct sockaddr *>(io_uring_recvmsg_name(hdr));
            socklen_t peerLen = hdr->namelen;

            if (peerAddr->sa_family != AF_INET)
            {
                return Gen::CONTINUE;
            }

            struct sockaddr_in localAddr{};
            socklen_t localAddrLen = sizeof(localAddr);
            if (getsockname(Gen::activeThreads[thread].udpFd, reinterpret_cast<struct sockaddr *>(&localAddr), &localAddrLen) != 0)
            {
                return Gen::CONTINUE;
            }

            quiche_recv_info info = {
                .from = peerAddr,
                .from_len = peerLen,
                .to = reinterpret_cast<struct sockaddr *>(&localAddr),
                .to_len = localAddrLen,
            };

            std::array<uint8_t, 18> id;
            generateDcid(id);

            std::cout << "GENERATED: ";

            for (auto c : id)
            {
                printf("%d", c);
                std::cout << " ";
            }

            std::cout << std::endl;

            std::string key;
            key.reserve(sizeof(sockaddr_in) + dcidLen);
            key.append(reinterpret_cast<const char *>(peerAddr), peerLen);
            key.append(reinterpret_cast<const char *>(dcid), dcidLen);

            quiche_conn *quicConn = quiche_accept(
                id.data(), id.size(),
                dcid, dcidLen,
                reinterpret_cast<struct sockaddr *>(&localAddr), localAddrLen,
                peerAddr, peerLen,
                conf);

            if (!quicConn)
            {
                std::cout << "conn is nullptr" << std::endl;
                return Gen::CONTINUE;
            }

            SSL *ssl = (SSL *)quiche_conn_get_ssl(quicConn);

            Gen::activeThreads[thread].h3ssl[key].dcid = id;
            Gen::activeThreads[thread].h3ssl[key].ssl = ssl;

            Gen::activeThreads[thread].h3connections[key].state = Gen::STATE_TLS_WAKEUP;
            Gen::activeThreads[thread].h3connections[key].streamId = 0;

            Gen::activeThreads[thread].h3ssl[key].ioCtx.thread = thread;
            Gen::activeThreads[thread].h3ssl[key].ioCtx.key = key;
            Gen::activeThreads[thread].h3ssl[key].ioCtx.protocol = Gen::H3;

            SSL_set_app_data(ssl, &Gen::activeThreads[thread].h3ssl[key].ioCtx);

            auto &conn = Gen::activeThreads[thread].h3connections[key];

            ssize_t recvLen = quiche_conn_recv(quicConn, quicPayload, quicPayloadLen, &info);
            std::cout << "RECV RESULT: " << recvLen << " (payload len was " << quicPayloadLen << ")" << std::endl;

            uint8_t out[MAX_DATAGRAM_SIZE];

            while (true)
            {
                ssize_t written = quiche_conn_send(quicConn, out, sizeof(out), &conn.send_info);

                if (written == QUICHE_ERR_DONE)
                {
                    break;
                }

                if (written < 0)
                {
                    break;
                }

                std::cout << "WRITTEN: " << written << std::endl;

                conn.iov.iov_base = out;
                conn.iov.iov_len = written;

                conn.msg.msg_name = &conn.send_info.to;
                conn.msg.msg_namelen = conn.send_info.to_len;
                conn.msg.msg_iov = &conn.iov;
                conn.msg.msg_iovlen = 1;

                pipeline->queueWriteClient(conn);
            }
        }

        io_uring_submit(ring);
        return Gen::CONTINUE;
    }

    case ::H3::Gen::H3_STATE_WRITE_CLIENT:
    {
        std::cout << "I WROTE SUCCESSFULLY" << std::endl;
        io_uring_submit(ring);
        return Gen::CONTINUE;
    }
    }

    return 0;
}

int Protocols::H3::wakeup(int res)
{
}

void Protocols::H3::generateDcid(std::array<uint8_t, 18> &out)
{
    thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (auto &b : out)
        b = static_cast<uint8_t>(dist(rng));
}