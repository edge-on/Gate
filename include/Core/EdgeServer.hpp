#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <cstring>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <unordered_map>

#include "Commands/Commands.hpp"

#include "Utility/Epoll.hpp"

class EdgeServer
{
public:
    EdgeServer();

    EdgeServer &setPort(int PORT);

    void start();
    void initClientServer();
    void initSSL();

    enum ConnType
    {
        CLIENT,
        BRIDGE
    };

    struct Connection
    {
        int fd;
        int peer_fd;

        SSL *ssl;

        bool handshake_done = false;

        bool tcp_connected = false;

        ConnType type;

        std::string buffer;
        int cmd;

        std::string in_buffer;
        std::string out_buffer;
        int write_offset = 0;

        bool epollout = false;
    };

    struct Response
    {
        int command;
        std::string payload;
    };

    void sendCommand(Connection &conn, int &cmd, std::string &paylod);

    void closeConnection(Connection &conn);

    std::unordered_map<int, Connection> connections;

private:
    // Client Addr
    int client_port = 8080;
    int client_listen;

    // Epoll
    int epoll_fd;
    int MAX_EVENTS = 10;

    // SSL
    SSL_CTX *ctx;
    SSL_CTX *bridge_ctx;

    // Bridge
    int bridge_port = 9001;

    bool isLogging = false;

    int handleRead(Connection &conn);
    int handleWrite(Connection &conn);

    void startWorkers();
};