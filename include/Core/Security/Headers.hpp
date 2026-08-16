#pragma once

#include <vector>

#include "Utils/Http.hpp"

namespace Security
{
    class Headers
    {
    public:
        static inline const std::vector<std::string> kAllowedBotKeywords = {
            "googlebot",
            "google-inspectiontool",
            "googleother",
            "adsbot-google",
            "mediapartners-google",
            "apis-google",
            "bingbot",
            "msnbot",
            "bingpreview",
            "slurp",
            "duckduckbot",
            "baiduspider",
            "yandexbot",
            "sogou",
            "exabot",
            "facebookexternalhit",
            "twitterbot",
            "linkedinbot",
            "applebot",
            "petalbot",
        };
        
        enum class RequestStatus
        {
            VALID_CLIENT = 1,
            BLOCKED = 2,
            INVALID_HTTP = 3
        };

        static RequestStatus validateReq(char *req, ssize_t len);
        static bool isBotUserAgent(const std::string &userAgent);

        static bool isAllowedCrawler(const std::string &lowerUa);
    };
} // namespace Security
