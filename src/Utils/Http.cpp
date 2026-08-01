#include "Utils/Http.hpp"

const char *Utils::Http::getRootDomainPtr(const char *host, size_t len)
{
    if (!host || len == 0)
        return host;

    int dotCount = 0;
    const char *p = host + len;

    while (p > host)
    {
        --p;
        if (*p == '.')
        {
            dotCount++;
            if (dotCount == 2)
            {
                return p + 1;
            }
        }
    }

    return host;
}

std::string Utils::Http::getHost(const char *buffer, size_t buffer_len)
{
    std::string_view data(buffer, buffer_len);

    auto it = std::search(
        data.begin(), data.end(),
        "host:", "host:" + 5,
        [](char a, char b)
        {
            return (a | 32) == b;
        });

    if (it == data.end())
        return "";

    auto start = it + 5;

    while (start != data.end() && (*start == ' ' || *start == '\t'))
    {
        start++;
    }

    auto end = start;
    while (end != data.end() && *end != '\r' && *end != '\n')
    {
        end++;
    }

    return std::string(start, end);
}

std::string Utils::Http::getPath(const char *buffer, size_t buffer_len)
{
    std::string_view data(buffer, buffer_len);

    auto method_end = std::find(data.begin(), data.end(), ' ');
    if (method_end == data.end())
        return "";

    auto start = method_end + 1;

    while (start != data.end() && (*start == ' ' || *start == '\t'))
    {
        start++;
    }

    auto end = start;
    while (end != data.end() && *end != ' ' && *end != '\r' && *end != '\n')
    {
        end++;
    }

    return std::string(start, end);
}