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

            std::vector<std::string> buckets(1000);
            std::hash<std::string> hasher;

            for (auto &[domain, metrics] : Gen::zones)
            {
                size_t bucket = hasher(domain) % 1000;
                std::string &b_stream = buckets[bucket];

                if (metrics.inbound > 0)
                    b_stream.append("HINCRBY d_bucket:").append(std::to_string(bucket)).append(" i_").append(domain).append(" ").append(std::to_string(metrics.inbound)).append("\r\n");

                if (metrics.outbound > 0)
                    b_stream.append("HINCRBY d_bucket:").append(std::to_string(bucket)).append(" o_").append(domain).append(" ").append(std::to_string(metrics.outbound)).append("\r\n");

                if (metrics.dnsQueries > 0)
                    b_stream.append("HINCRBY d_bucket:").append(std::to_string(bucket)).append(" dq_").append(domain).append(" ").append(std::to_string(metrics.dnsQueries)).append("\r\n");

                metrics.inbound = 0;
                metrics.outbound = 0;
                metrics.dnsQueries = 0;
            }

            for (auto bucket : buckets)
            {
                redisReply *reply = (redisReply *)redisCommand(Main::redis, bucket.data());
                if (reply != NULL)
                {
                    freeReplyObject(reply);
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