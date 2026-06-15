#pragma once

#include <liburing.h>

#include "Core/Gen/Gen.hpp"
#include "Core/Uring/Pipeline.hpp"
#include "Core/Proxy/Proxy.hpp"

#include "Main.hpp"

class Core
{
public:
    Core();
    ~Core();

    void start();

private:
    void worker(int thread);
};