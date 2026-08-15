#pragma once

#include <thread>
#include <chrono>
#include <iostream>

#include "Main.hpp"

#include "Core/Gen/Gen.hpp"

#include "Helper/VNStat.hpp"

namespace Thread
{
    class Operational
    {
    public:
        static void operationalWorker(int thread);
    };
} // namespace Thread
