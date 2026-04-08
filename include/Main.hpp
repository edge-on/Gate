#pragma once 

#include <signal.h>

#include "Core/EdgeServer.hpp"
#include "Atlas/Atlas.hpp"

#include "Dotenv/Dotenv.hpp"

class Main {
public:
    static Dotenv *dotenv;
};