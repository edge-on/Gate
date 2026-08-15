#include "Helper/VNStat.hpp"

uint64_t Helper::VNStat::getDailyTraffic()
{
    std::string interface = Helper::Process::execCommand("ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+'");

    std::string cmd = "vnstat --json d --limit 1 -i " + interface;
    std::string vnstat = Helper::Process::execCommand(cmd.data());
    auto json = nlohmann::json::parse(vnstat);

    uint64_t rx = json["interfaces"][0]["traffic"]["day"][0]["rx"];
    uint64_t tx = json["interfaces"][0]["traffic"]["day"][0]["tx"];

    return rx + tx;
}