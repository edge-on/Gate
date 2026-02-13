#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <openssl/ssl.h>
#include <unordered_map>

class EdgeServer
{
public:
    EdgeServer();
    
    EdgeServer& setPort(int PORT);
    void start();

    struct Connection
    {
        int fd;
        SSL* ssl;
        bool handshake_done;
    };
    
    std::unordered_map<int, Connection> connections;

private:
    int PORT = 8080;
    int MAX_EVENTS = 10;

    int server_fd;

    std::vector<std::thread> workers;

    void startWorker();

    int makeNonBlocking(int sfd);
};