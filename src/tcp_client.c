#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 5000

int main(void) {
	int sock;
	struct sockaddr_in server;
	const  char *message = "HI from PC1";

	sock  = socket(AF_INET, SOCK_STREAM, 0);
	
	if(sock < 0){
		perror("socket");
		return 1;
}

memset(&server, 0, sizeof(server));
server.sin_family = AF_INET;
server.sin_port = htons(PORT);
server.sin_addr.s_addr = inet_addr("10.0.3.2");

if(connect(sock, (struct sockaddr *)&server, sizeof(server)) <0){
	perror("connect");
	close(sock);
	return 1;
}

printf("PC1: Connected to PC2\n");

size_t  length = strlen(message);
size_t sent = 0;

while(sent < length){
	ssize_t n =  send(sock, message + sent, length - sent,0);
	if(n <=0){
		perror("send");
		close(sock);
		return 1;
}

sent += (size_t)n;

}
printf("PC1: Message sent successfully\n");

close(sock);
return 0;
} 
