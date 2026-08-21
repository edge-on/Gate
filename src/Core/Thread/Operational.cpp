#include "Core/Thread/Operational.hpp"

void Thread::Operational::operationalWorker(int thread)
{
    int seconds = 0;

    while (true)
    {
        seconds++;

        if (seconds == 60)
        {
            seconds = 0;

            uint64_t minute_timestamp = std::chrono::duration_cast<std::chrono::minutes>(std::chrono::system_clock::now().time_since_epoch()).count() * 60;

            redisAppendCommand(Main::redis, "MULTI");
            size_t active_commands = 0;

            for (auto &[domain, metrics] : Gen::zones)
            {
                if (metrics.inbound == 0 && metrics.outbound == 0 && metrics.dnsQueries == 0)
                    continue;

                if (metrics.inbound > 0)
                {
                    redisAppendCommand(Main::redis, "HINCRBY metrics:domain:%s i:%llu %llu",
                                       domain.c_str(), minute_timestamp, metrics.inbound);
                    metrics.inbound = 0;
                    active_commands++;
                }

                if (metrics.outbound > 0)
                {
                    redisAppendCommand(Main::redis, "HINCRBY metrics:domain:%s o:%llu %llu",
                                       domain.c_str(), minute_timestamp, metrics.outbound);
                    metrics.outbound = 0;
                    active_commands++;
                }

                if (metrics.dnsQueries > 0)
                {
                    redisAppendCommand(Main::redis, "HINCRBY metrics:domain:%s dq:%llu %llu",
                                       domain.c_str(), minute_timestamp, metrics.dnsQueries);
                    metrics.dnsQueries = 0;
                    active_commands++;
                }

                active_commands++;
            }

            if (active_commands > 0)
            {
                redisAppendCommand(Main::redis, "EXEC");

                size_t total_responses = active_commands + 2;
                for (size_t i = 0; i < total_responses; ++i)
                {
                    redisReply *reply = nullptr;
                    if (redisGetReply(Main::redis, (void **)&reply) == REDIS_OK && reply != nullptr)
                    {
                        freeReplyObject(reply);
                    }
                }
            }

            Origin::getNewVersions();
        }

        ssize_t rpsCount = 0;
        ssize_t acCount = 0;

        for (const auto &[threadId, threadObj] : Gen::activeThreads)
        {
            rpsCount += threadObj.connections.size();
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