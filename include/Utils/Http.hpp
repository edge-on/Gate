#pragma once

#include <string>
#include <string_view>

namespace Utils
{
    class Http
    {
    public:
        static std::string getHost(const char *buffer, size_t buffer_len);
    };
} // namespace Utils
