#pragma once

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdio.h>

#include "Utils/Uring/H1/H1.hpp"
#include "Utils/Uring/H3/H3.hpp"
#include "Utils/Uring/Uring.hpp"

class Proxy
{
public:
    static int initServer(int port);
    static int initUdpServer(int port);

    static int createOriginSocket(char *ip, int port, sockaddr_in &outAddr);
    static int createResolverSocket();
};