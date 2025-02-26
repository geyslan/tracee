#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_SOCKET_PATH "/tmp/sock"

int main()
{
    int client_fd;
    struct sockaddr_un server_addr, client_addr;
    char client_socket_path[108]; // Max UNIX socket path size

    // Create client socket
    client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Zero out struct
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;

    // Generate unique client socket path
    snprintf(client_socket_path, sizeof(client_socket_path), "/tmp/sock_client_%d", getpid());
    strncpy(client_addr.sun_path, client_socket_path, sizeof(client_addr.sun_path) - 1);

    // Bind client socket
    unlink(client_socket_path); // Ensure no stale file exists
    if (bind(client_fd, (struct sockaddr*) &client_addr, sizeof(client_addr)) == -1) {
        perror("bind");
        close(client_fd);
        exit(EXIT_FAILURE);
    }

    printf("Client socket bound to: %s\n", client_socket_path);

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SERVER_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // Connect to the server
    if (connect(client_fd, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(client_fd);
        unlink(client_socket_path);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server!\n");

    // Cleanup
    close(client_fd);
    unlink(client_socket_path);

    return 0;
}
