#include "Core/Transports/HTTP/HTTP.hpp"

void Transports::HTTP::parseHttp(char *body, ssize_t length, ::H3::Gen::ReqIOCtx &req)
{
    bool isHeaderPack = false;

    std::string_view data = std::string_view(body);

    if (data.find('\r\n\r\n') != std::string::npos)
        isHeaderPack = true;

    if (isHeaderPack)
    {
        std::string_view firstLine = data.substr(0, data.find('\n'));

        // For base data
        std::vector<std::string_view> results;
        ssize_t start = 0;
        ssize_t end = firstLine.find(' ');

        while (end != std::string::npos)
        {
            results.push_back(firstLine.substr(start, end - start));
            start = end + 1;
            end = firstLine.find(' ', start);
        }

        results.push_back(firstLine.substr(start));

        if (results.size() <= 1)
            return;

        req.status = strndup(results[1].data(), results[1].size()); // Status = Indis 1
    }
}