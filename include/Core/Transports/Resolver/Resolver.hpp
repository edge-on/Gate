#pragma once

#include <string.h>

#include "DNS/DNSClient.hpp"

namespace Transports
{
    class Resolver
    {
    public:
        struct ResolverPacket
        {
            char resolverPacket[512];
            ssize_t outLen;
        };

        static ResolverPacket getResolverPacket(char *host /* in */);
    };
} // namespace Transports
