#include "Helper/VNStat.hpp"

uint64_t Helper::VNStat::getDailyTraffic()
{
    std::string interface = Helper::Process::execCommand("ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+'");

    std::string cmd = "vnstat --json d --limit 1 -i " + interface;
    std::string vnstat = Helper::Process::execCommand(cmd.data());
    auto json = nlohmann::json::parse(vnstat);

    const auto &day_node = json["interfaces"][0]["traffic"]["day"][0];

    uint64_t rx = (day_node.contains("rx") && day_node["rx"].is_number()) ? day_node["rx"].get<uint64_t>() : 0;
    uint64_t tx = (day_node.contains("tx") && day_node["tx"].is_number()) ? day_node["tx"].get<uint64_t>() : 0;

    return rx + tx;
}