#pragma once

#include <cstring>
#include <string>
#include <string_view>
#include <algorithm>
#include <iostream>

namespace Utils
{
    class Http
    {
    public:
        static const char *getRootDomainPtr(const char *host, size_t len);

        static std::string getHeader(const char *buffer, size_t buffer_len, const char* header);

        static std::string getHost(const char *buffer, size_t buffer_len);
        static std::string getPath(const char *buffer, size_t buffer_len);
    };
} // namespace Utils
