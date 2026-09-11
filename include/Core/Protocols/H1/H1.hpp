#pragma once

#include <liburing.h>
#include <openssl/ssl.h>

#include "Main.hpp"

#include "Core/Gen/H1/Gen.hpp"

#include "Core/Transports/Proxy/Proxy.hpp"
#include "Core/Transports/Resolver/Resolver.hpp"

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
        H1(struct io_uring *ring /* in */, int thread /* in */, Pipeline::H1 *pipeline /* in */, SSL_CTX *ctx /* in */);
        int run(struct io_uring_cqe *cqe /* in */);
        int wakeup(int res /* in */);

    private:
        struct io_uring *ring;
        int thread;
        Pipeline::H1 *pipeline;
        SSL_CTX *ctx;
    };
} // namespace Protocols