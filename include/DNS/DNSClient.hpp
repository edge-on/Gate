#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <random>

class DNSClient
{
private:
    std::string server_ip;
    int port;

public:
    DNSClient(std::string ip, int p);

    static void formatName(char *dns, const std::string &host);
    static std::string getRandomIP(std::vector<std::string> ips);
};