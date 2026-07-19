#include "DNS/DNSClient.hpp"

DNSClient::DNSClient(std::string ip, int p = 53) : server_ip(ip), port(p) {}

void DNSClient::formatName(unsigned char *dns, const std::string &host)
{
    int lock = 0;
    for (int i = 0; i < host.length(); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
                *dns++ = host[lock];
            lock++;
        }
    }
    *dns++ = host.length() - lock;
    for (; lock < host.length(); lock++)
        *dns++ = host[lock];
    *dns++ = 0;
}

std::vector<std::string> DNSClient::resolve(const std::string &hostname)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &dest.sin_addr);

    unsigned char packet[512] = {0};

    packet[0] = 0x12;
    packet[1] = 0x34;
    packet[2] = 0x01;
    packet[3] = 0x00;
    packet[5] = 1;

    unsigned char *qname = &packet[12];
    formatName(qname, hostname);

    int qlen = strlen((char *)qname) + 1;
    packet[12 + qlen + 1] = 1;
    packet[12 + qlen + 3] = 1;

    sendto(sock, packet, 12 + qlen + 4, 0, (struct sockaddr *)&dest, sizeof(dest));

    unsigned char buffer[512];
    ssize_t received = recv(sock, buffer, 512, 0);
    close(sock);

    std::vector<std::string> ips;
    int count = ntohs(*(uint16_t *)&buffer[6]);
    unsigned char *p = &buffer[12 + qlen + 4];

    for (int i = 0; i < count; i++)
    {
        p += 2;
        uint16_t type = ntohs(*(uint16_t *)p);
        p += 8;
        uint16_t len = ntohs(*(uint16_t *)p);
        p += 2;

        if (type == 1)
        {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, p, ip_str, INET_ADDRSTRLEN);
            ips.push_back(std::string(ip_str));
        }
        p += len;
    }
    return ips;
}

std::string DNSClient::getRandomIP(const std::string &hostname)
{
    std::vector<std::string> ips = resolve(hostname);
    if (ips.empty())
        return "";

    static std::mt19937 rng(time(0));
    std::uniform_int_distribution<size_t> dist(0, ips.size() - 1);
    return ips[dist(rng)];
}