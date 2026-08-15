#pragma once

#include <vector>

#include "Utils/Http.hpp"

namespace Security
{
    class Headers
    {
    public:
        enum class RequestStatus
        {
            VALID_CLIENT = 1,
            BLOCKED = 2,
            INVALID_HTTP = 3
        };

        static RequestStatus validateReq(char *req, ssize_t len);
        static bool isBotUserAgent(const std::string &userAgent);
    };
} // namespace Security
