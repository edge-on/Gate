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

#include "Commands/Commands.hpp"

class EdgeServer
{
public:
    EdgeServer();

    EdgeServer &setPort(int PORT);

    void start();

    void initClientServer();
    void initBackendServer();

    void initSSL();

    void sendCommand(SSL *ssl, int &cmd, std::string &paylod);

    enum ConnType
    {
        BACKEND,
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
        SSL *ssl;

        bool handshake_done = false;
        bool session_initialized = false;

        ConnType type;

        ReadState state = ReadState::READ_CMD;
        uint8_t cmd = 0;
        uint32_t len = 0;
        std::vector<char> buffer;
    };

    std::unordered_map<int, Connection> connections;

    std::unordered_map<std::string, int> backends;

private:
    int client_port = 8080;
    int backend_port = 9000;

    int MAX_EVENTS = 10;

    int client_listen, backend_listen;

    SSL_CTX *ctx;

    int handleCommands(Connection &conn, int &command, std::string &payload);

    bool read_exact(SSL *ssl, void *buffer, size_t len);

    int handleBackend(Connection &conn);
    int handleClient(Connection &conn);

    void startWorkers();

    int makeNonBlocking(int sfd);
};