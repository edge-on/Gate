#pragma once

#include <string>
#include <string_view>
#include <stdexcept>
#include <iostream>
#include <array>
#include <memory>

namespace Helper
{
    class Process
    {
    public:
        static std::string execCommand(const char *command);
    };
} // namespace Helper
