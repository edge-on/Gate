#include "Core/Thread/Operational.hpp"

void Thread::Operational::operationalWorker(int thread)
{
    int seconds = 0;

    while (true)
    {
        seconds++;

        if (seconds == 1)
        {
            seconds = 0;

            Origin::getNewVersions();
        }

        ssize_t rpsCount = 0;
        ssize_t acCount = 0;

        for (const auto &[threadId, threadObj] : Gen::activeThreads)
        {
            rpsCount += threadObj.connections.size();

            int a = 0;
            int c = 0;
            for (auto &ba : threadObj.connections)
            {
                if (ba.second.type == Gen::TYPE_CLIENT)
                    a++;

                if (ba.second.type == Gen::TYPE_ORIGIN)
                    c++;
            }

            std::cout << "Type CLIENT: " << a << std::endl;
            std::cout << "Type ORIGIN: " << c << std::endl;

            acCount += threadObj.activeConnections;
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