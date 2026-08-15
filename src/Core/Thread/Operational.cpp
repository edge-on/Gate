#include "Core/Thread/Operational.hpp"

void Thread::Operational::operationalWorker(int thread)
{
    while (true)
    {
        ssize_t rpsCount = 0;
        ssize_t acCount = 0;

        for (auto thread : Gen::activeThreads)
        {
            rpsCount += thread.second.connections.size();
            acCount += thread.second.activeConnections;
        }

        std::string key = Main::country + "-" + Main::city + "-" + Main::code;
        std::string rpsKey = "rps-" + key;
        std::string activeConnections = "ac-" + key;
        std::string trafficKey = "traffic-" + key;

        redisReply *reply = (redisReply *)redisCommand(Main::redis, "SET %s %d", rpsKey.c_str(), rpsCount);
        if (reply != NULL)
        {
            freeReplyObject(reply);
        }

        redisReply *reply2 = (redisReply *)redisCommand(Main::redis, "SET %s %d", activeConnections.c_str(), acCount);
        if (reply2 != NULL)
        {
            freeReplyObject(reply2);
        }

        redisReply *reply3 = (redisReply *)redisCommand(Main::redis, "SET %s %d", trafficKey.c_str(), Helper::VNStat::getDailyTraffic());
        if (reply3 != NULL)
        {
            freeReplyObject(reply3);
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}