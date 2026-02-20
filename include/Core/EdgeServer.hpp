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
        CLIENT
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
        int bridge_fd;

        SSL *ssl;

        bool handshake_done = false;
        bool session_initialized = false;

        ConnType type;

        ReadState state = ReadState::READ_CMD;
        uint8_t cmd = 0;
        uint32_t len = 0;
        std::vector<char> buffer;
    };

    struct Bridge {
        int fd;

        SSL *ssl;

        bool handshake_done = false;
    };

    std::unordered_map<int, Connection> connections;
    std::unordered_map<int, Bridge> bridges;

private:
    // Client Addr
    int client_port = 8080;
    int client_listen;

    // Epoll
    int MAX_EVENTS = 10;

    // SSL
    SSL_CTX *ctx;

    // Bridge 
    int bridge_port = 9001;

    int handleClient(Connection &conn);
    int makeNonBlocking(int sfd);

    void startWorkers();
};