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
    int id = (int)(data & 0xFFFFFFFF);
    int opType = (int)(data >> 32);

    int res = cqe->res;
    bool hasMore = cqe->flags & IORING_CQE_F_MORE;
    io_uring_cqe_seen(ring, cqe);

    if (res < 0)
    {
        return Gen::CONTINUE;
    }

    auto gConn = Gen::activeThreads[thread].h3connections.find(id);
    auto &conn = gConn->second;

    switch (opType)
    {
    case ::H3::Gen::H3_STATE_READ_CLIENT:
    {
        std::cout << "I recv for " << id << std::endl;

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

        /*
            TYPES
               0x01 = HEADER INITIAL
               0x02 = RETRY
               0x03 = HANDSHAKE
               0x04 = 0-RTT
        */
        std::cout << "I RECV";
        printf("%d", type);
        std::cout << std::endl;

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

            uint32_t id = Gen::activeThreads[thread].h3connections.size() + 1;

            quiche_conn *quicConn = quiche_accept(
                (uint8_t *)id, 5,
                dcid, dcidLen,
                reinterpret_cast<struct sockaddr *>(&localAddr), localAddrLen,
                peerAddr, peerLen,
                conf);

            if (quicConn)
            {
                return Gen::CONTINUE;
            }

            SSL *ssl = (SSL *)quiche_conn_get_ssl(quicConn);

            Gen::activeThreads[thread].h3ssl[id].dcid = id;
            Gen::activeThreads[thread].h3ssl[id].ssl = ssl;

            auto *h3conn = new ::H3::Gen::H3Connection();
            h3conn->state = Gen::STATE_TLS_WAKEUP;
            h3conn->streamId = 0;

            Gen::activeThreads[thread].h3ssl[id].ioCtx.h3conn = h3conn;
            Gen::activeThreads[thread].h3ssl[id].ioCtx.protocol = Gen::H3;

            SSL_set_app_data(ssl, &Gen::activeThreads[thread].h3ssl[id].ioCtx);

            quiche_conn_recv(quicConn, quicPayload, quicPayloadLen, &info);

            int r = SSL_accept(ssl);
            int err = SSL_get_error(ssl, r);

            std::cout << err << std::endl;
            if (err == SSL_ERROR_WANT_READ)
            {
                pipeline->queueReadClient(id);
                io_uring_submit(ring);
            }
        }
        else
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
        }

        return Gen::CONTINUE;
    }
    }

    return 0;
}

int Protocols::H3::wakeup(int res)
{
}

std::string Protocols::H3::generateDcid()
{
    constexpr char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    constexpr size_t length = 18;

    std::string result;
    result.resize(length);

    thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);

    for (size_t i = 0; i < length; ++i)
    {
        result[i] = charset[dist(rng)];
    }

    return result;
}