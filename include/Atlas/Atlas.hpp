#pragma once

#include "Cassandra/Cassandra.hpp"

class Atlas
{
public:
    Atlas();
    ~Atlas();

private:
    Cassandra* cas;
};