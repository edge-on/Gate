#pragma once

#include <signal.h>

#include "Core/Core.hpp"

#include "Dotenv/Dotenv.hpp"

class Main
{
public:
    static Dotenv *dotenv;

    static std::vector<int> listeners;
};