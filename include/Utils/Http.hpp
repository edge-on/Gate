#pragma once

#include <string>
#include <string_view>
#include <algorithm>

namespace Utils
{
    class Http
    {
    public:
        static std::string getHost(const char *buffer, size_t buffer_len);
        static std::string getPath(const char *buffer, size_t buffer_len);
    };
} // namespace Utils
