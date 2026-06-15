#pragma once

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdio.h>

#include "Utils/Uring.hpp"

class Proxy
{
public:
    static int initServer(int port);
};