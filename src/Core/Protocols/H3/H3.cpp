#include "Core/Protocols/H3/H3.hpp"

int Protocols::H3::run(struct io_uring_cqe *cqe, struct io_uring *ring, int thread, Pipeline::H3 *pipeline, struct quiche_config *conf)
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
            std::cout << "This is an initial pack" << std::endl;
        }

        struct sockaddr_in dummyPeerAddr{};
        dummyPeerAddr.sin_family = AF_INET;
        socklen_t dummyPeerAddrLen = sizeof(dummyPeerAddr);

        struct sockaddr_in localAddr{};
        localAddr.sin_family = AF_INET;
        socklen_t localAddrLen = sizeof(localAddr);

        quiche_conn *conn = quiche_accept(scid, scidLen,
                                          dcid, dcidLen,
                                          (struct sockaddr *)&localAddr, localAddrLen,
                                          (struct sockaddr *)&dummyPeerAddr, dummyPeerAddrLen,
                                          conf);

        if (conn == nullptr)
            std::cout << "accept is not successfull" << std::endl;

        auto *ctx = (SSL_CTX *)quiche_config_get_ssl_ctx(conf);

        if (ctx != nullptr)
            std::cout << "I take ssl pointer from rust" << std::endl;

        if (SSL_CTX_get0_certificate(ctx) != nullptr)
            std::cout << "VALID" << std::endl;

        break;
    }
    }

    return 0;
}