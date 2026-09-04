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

        void establisheConnection(std::string oldKey, std::string newKey);
    private:
        int thread;

        Pipeline::H3 *pipeline;

        struct io_uring *ring;
        struct quiche_config *conf;

        SSL_CTX *ctx;
    };
} // namespace HTTP
