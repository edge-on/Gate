#pragma once

#include <string>
#include <nlohmann/json.hpp>

#include "Helper/Process.hpp"

namespace Helper
{
    class VNStat
    {
    public:
        static uint64_t getDailyTraffic();
    };
} // namespace Helper
