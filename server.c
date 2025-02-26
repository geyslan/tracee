#define _GNU_SOURCE // Required for accept4()
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/sock"

int main()
{
    int server_fd, client_fd;
    struct sockaddr_un addr;

    // Create UNIX domain socket
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Ensure addr is zeroed before use
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1); // Ensure null termination

    // Remove any existing socket file
    unlink(SOCKET_PATH);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr*) &addr, sizeof(struct sockaddr_un)) == -1) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s...\n", SOCKET_PATH);

    // Accept a connection using accept4()
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    client_fd = accept4(server_fd, (struct sockaddr*) &client_addr, &client_len, SOCK_CLOEXEC);
    if (client_fd == -1) {
        perror("accept4");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Connection accepted! Client path: %s\n", client_addr.sun_path);

    // Cleanup
    close(client_fd);
    close(server_fd);
    unlink(SOCKET_PATH);

    return 0;
}
