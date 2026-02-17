#include "Atlas/Atlas.hpp"

Atlas::Atlas() {
    cas = new Cassandra();
    
    if(cas->connect()) {
        std::cout << "ScyllaDB connection is successfully" << std::endl;

        client_fd = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in serverAddress;
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(4000);
        serverAddress.sin_addr.s_addr = INADDR_ANY;

        connect(client_fd, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

        const char* command = "command_here";
        send(client_fd, command, strlen(command), 0);

        close(client_fd);
    } else {
        std::cout << "ScyllaDB connection is not successfully" << std::endl;
    }
}

Atlas::~Atlas() {

}

bool Atlas::connectToAtlas() {

}

std::string Atlas::sendToAtlas() {

}