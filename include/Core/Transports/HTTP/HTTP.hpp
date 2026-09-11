#pragma once

#include "Core/Gen/H3/Gen.hpp"

namespace Transports
{
    class HTTP
    {
    public:
        static void parseHttp(char *body /* in */, ssize_t length /* in */, ::H3::Gen::ReqIOCtx &req /* out */);
    };
} // namespace Transports