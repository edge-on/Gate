#include "Core/Thread/Operational.hpp"

void Thread::Operational::operationalWorker(int thread) {
    while (true)
    {
        ssize_t rpsCount;
        
        for(auto thread : Gen::activeThreads) {
            rpsCount += thread.second.connections.size();
        }

        std::string key = "rps-" + Main::country + "-" + Main::city + "-" + Main::code;

        redisReply *reply = (redisReply *)redisCommand(Main::redis, "SET %s %d", key.c_str(), rpsCount);
        if (reply != NULL)
        {
            freeReplyObject(reply);
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}