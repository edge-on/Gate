#include "Utils/Http.hpp"

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