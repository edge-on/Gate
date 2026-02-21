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

class EdgeServer
{
public:
    EdgeServer();

    EdgeServer &setPort(int PORT);

    void start();
    void initClientServer();
    void initSSL();
    void sendCommand(SSL *ssl, int &cmd, std::string &paylod);

    enum ConnType
    {
        CLIENT,
        BRIDGE
    };

    enum class ReadState
    {
        READ_CMD,
        READ_LEN,
        READ_PAYLOAD
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

        bool epollout = false;
    };

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

    int handleRead(Connection &conn);
    int handleWrite(Connection &conn);

    void disableWrite(int fd);
    void enableWrite(int fd);

    int makeNonBlocking(int sfd);

    void startWorkers();
};