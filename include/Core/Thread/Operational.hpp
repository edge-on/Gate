#pragma once

#include <thread>
#include <chrono>
#include <iostream>

#include "Main.hpp"

#include "Core/Gen/Gen.hpp"

namespace Thread
{
    class Operational
    {
    public:
        static void operationalWorker(int thread);
    };
} // namespace Thread
