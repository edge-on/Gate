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

    void formatName(unsigned char *dns, const std::string &host);

public:
    DNSClient(std::string ip, int p);

    std::vector<std::string> resolve(const std::string &hostname);
    std::string getRandomIP(const std::string &hostname);
};