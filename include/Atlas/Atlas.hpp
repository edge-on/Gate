#pragma once

#include <sys/epoll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <openssl/ssl.h>
#include <unordered_map>

#include "Cassandra/Cassandra.hpp"

class Atlas
{
public:
    Atlas();
    ~Atlas();

private:
    Cassandra* cas;

    int client_fd;

    int PORT;
    
    SSL_CTX* ctx;
};