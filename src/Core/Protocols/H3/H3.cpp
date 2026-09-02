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
    int fd = (int)(data & 0xFFFFFFFF);
    int opType = (int)(data >> 32);

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

        struct io_uring_recvmsg_out *hdr = reinterpret_cast<struct io_uring_recvmsg_out *>(raw);

        uint8_t *quicPayload = reinterpret_cast<uint8_t *>(raw + sizeof(struct io_uring_recvmsg_out) + hdr->namelen);
        size_t quicPayloadLen = hdr->payloadlen;

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
        if (rc == 0 && type == 0x01)
        {
            struct sockaddr_in dummyPeerAddr{};
            dummyPeerAddr.sin_family = AF_INET;
            socklen_t dummyPeerAddrLen = sizeof(dummyPeerAddr);

            struct sockaddr_in localAddr{};
            localAddr.sin_family = AF_INET;
            socklen_t localAddrLen = sizeof(localAddr);

            std::array<char, 18> id;
            memcpy(id.data(), generateDcid().data(), 18);

            quiche_conn *conn = quiche_accept(
                reinterpret_cast<const uint8_t *>(id.data()), id.size(),
                dcid, dcidLen,
                (struct sockaddr *)&localAddr, localAddrLen,
                (struct sockaddr *)&dummyPeerAddr, dummyPeerAddrLen,
                conf);

            if (conn == nullptr)
            {
                return Gen::CONTINUE;
            }

            SSL *ssl = (SSL *)quiche_conn_get_ssl(conn);

            Gen::activeThreads[thread].h3ssl[id].dcid = id;
            Gen::activeThreads[thread].h3ssl[id].ssl = ssl;

            auto *h3conn = new ::H3::Gen::H3Connection();
            h3conn->state = Gen::STATE_TLS_WAKEUP;
            h3conn->streamId = 0;

            Gen::activeThreads[thread].h3ssl[id].ioCtx.h3conn = h3conn;
            Gen::activeThreads[thread].h3ssl[id].ioCtx.protocol = Gen::H3;

            SSL_set_app_data(ssl, &Gen::activeThreads[thread].h3ssl[id].ioCtx);

            return Gen::CONTINUE;
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