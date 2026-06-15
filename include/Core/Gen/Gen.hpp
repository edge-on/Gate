#pragma once

#include <thread>
#include <unordered_map>
#include <vector>

class Gen
{
public:
    typedef struct
    {
        std::thread::id id;
    } Thread;

    static std::vector<std::thread> threads;
    static std::unordered_map<int, Thread> activeThreads;
};