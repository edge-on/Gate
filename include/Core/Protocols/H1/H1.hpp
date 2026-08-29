#pragma once

#include <liburing.h>
#include <openssl/ssl.h>

#include "Main.hpp"

#include "Core/Gen/H1/Gen.hpp"

#include "Core/Proxy/Proxy.hpp"
#include "Core/Security/Headers.hpp"

#include "Utils/Http.hpp"
#include "DNS/DNSClient.hpp"
#include "Maxmind/DB.hpp"

#include "Core/Protocols/H1/Uring/Pipeline.hpp"

namespace Protocols
{
    class H1
    {
    public:
        static int run(struct io_uring_cqe *cqe, struct io_uring *ring, int thread, Pipeline::H1 *pipeline, SSL_CTX *ctx);
    };
} // namespace Protocols