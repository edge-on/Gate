#pragma once

#include <quiche.h>
#include <liburing.h>

#include "Core/Protocols/H3/Uring/Pipeline.hpp"

namespace Protocols
{
    class H3
    {
    public:
        static int run(struct io_uring_cqe *cqe, struct io_uring *ring, int thread, Pipeline::H3 *pipeline, SSL_CTX *ctx);
    };
} // namespace HTTP
