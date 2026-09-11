#pragma once

#include <quiche.h>
#include <liburing.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <string>
#include <random>

#include "Core/Protocols/H3/Uring/Pipeline.hpp"

#include "Core/Transports/Proxy/Proxy.hpp"
#include "Core/Transports/Resolver/Resolver.hpp"

#include "Core/Transports/HTTP/HTTP.hpp"

#include "Main.hpp"

namespace Protocols
{
    class H3
    {
    public:
        H3(struct io_uring *ring /* in */, int thread /* in */, Pipeline::H3 *pipeline /* in */, struct quiche_config *conf /* in */, SSL_CTX *ctx /* in */);
        int run(struct io_uring_cqe *cqe /* in */);
        int wakeup(int res /* in */);

        void generateDcid(std::array<uint8_t, 18> &out /* out */);
        void establisheConnection(::H3::Gen::H3Connection &conn /* in */);

        uint32_t createKeyPeering(std::string key /* in */);
        bool deleteKeyPeering(uint32_t keyPeering /* in */);
        bool versionMismatch(::H3::Gen::HdrInfoCtx infoCtx /* in */, struct sockaddr *peerAddr /* in */, ssize_t peerLen /* in */);

        static int forEachHeaderCallback(uint8_t *name, size_t nameLen, uint8_t *value, size_t valueLen, void *argp);

    private:
        int thread;

        Pipeline::H3 *pipeline;

        struct io_uring *ring;
        struct quiche_config *conf;

        SSL_CTX *ctx;
    };
} // namespace HTTP
