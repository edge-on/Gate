#include "Core/Proxy/Proxy.hpp"

int Proxy::initServer(int port)
{
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    int opt = 1;
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    Utils::Uring::makeNonBlocking(sockFd);

    if (bind(sockFd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("initServer bind");
        return -1;
    }

    if (listen(sockFd, SOMAXCONN) < 0)
    {
        perror("initServer listen");
        return -1;
    }

    return sockFd;
}

int Proxy::createOriginSocket(char *ip, int port)
{
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);

    if (connect(sockFd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        return -1;
    }

    return sockFd;
}