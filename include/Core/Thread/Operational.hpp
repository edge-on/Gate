#pragma once

#include <thread>
#include <chrono>
#include <iostream>

#include "Main.hpp"

#include "Core/Gen/H1/Gen.hpp"
#include "Core/Gen/H3/Gen.hpp"

#include "Helper/VNStat.hpp"

#include "Mmap/SSL.hpp"

namespace Thread
{
    class Operational
    {
    public:
        static void operationalWorker(int thread);
    };
} // namespace Thread
