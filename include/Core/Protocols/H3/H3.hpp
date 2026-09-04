#pragma once

#include <quiche.h>
#include <liburing.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <string>
#include <random>

#include "Core/Protocols/H3/Uring/Pipeline.hpp"

namespace Protocols
{
    class H3
    {
    public:
        H3(struct io_uring *ring, int thread, Pipeline::H3 *pipeline, struct quiche_config *conf, SSL_CTX *ctx);
        int run(struct io_uring_cqe *cqe);
        int wakeup(int res);

        void generateDcid(std::array<uint8_t, 18> &out);

        enum quiche_pkt_type
        {
            QUICHE_PACKET_TYPE_INITIAL = 1,
            QUICHE_PACKET_TYPE_RETRY = 2,
            QUICHE_PACKET_TYPE_HANDSHAKE = 3,
            QUICHE_PACKET_TYPE_ZERO_RTT = 4,
            QUICHE_PACKET_TYPE_SHORT = 5,
            QUICHE_PACKET_TYPE_VERSION_NEGOTIATION = 6,
        };

    private:
        int thread;

        Pipeline::H3 *pipeline;

        struct io_uring *ring;
        struct quiche_config *conf;

        SSL_CTX *ctx;
    };
} // namespace HTTP
