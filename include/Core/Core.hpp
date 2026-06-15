#pragma once

#include <liburing.h>

#include "Core/Gen/Gen.hpp"

#include "Main.hpp"

class Core
{
public:
    void start();

private:
    void worker(int thread);
};