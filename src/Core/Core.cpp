#include "Core/Core.hpp"

void Core::start()
{
    int threadCount = std::stoi(Main::dotenv->map["concurrency"]);

    for (int i = 0; i < threadCount; ++i)
    {
        Gen::threads.emplace_back(&Core::worker, this, i);
        Gen::activeThreads[i].id = Gen::threads[i].get_id();
    }

    for (auto &thread : Gen::threads)
    {
        thread.join();
    }
}

void Core::worker(int thread)
{
    while (true)
    {
        /* code */
    }
}