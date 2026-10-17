#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 5000
#define BUFFER_SIZE 1024
int main(void){
	int server_fd, client_fd;
	struct sockaddr_in address;
	char buffer[BUFFER_SIZE];


	server_fd = socket (AF_INET, SOCK_STREAM, 0);
	
	if(server_fd <0){
	perror("socket");
	return 1;
}

memset(&address, 0, sizeof(address));
address.sin_family = AF_INET;
address.sin_addr.s_addr = inet_addr("10.0.3.2");
address.sin_port =  htons(PORT);

if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
	perror("bind");
	close(server_fd);
	return 1;
}


if(listen(server_fd, 5)<0){
	perror("listen");
	
	close(server_fd);
	return 1;
}


printf("PC2 : Waiting for TCP connection \n");
fflush(stdout);

client_fd = accept(server_fd, NULL, NULL);

if(client_fd <0){
	perror("ACCEPT");
	close(server_fd);
	return 1;
}

ssize_t n = recv(client_fd, buffer, sizeof(buffer) -1, 0);

if(n > 0 ){
	
	buffer[n] = '\0';
	printf("It is received: %s\n", buffer);
}
	else if(n <0 ){
		perror("recv");
}

close(client_fd);
close(server_fd);
return 0;
}
