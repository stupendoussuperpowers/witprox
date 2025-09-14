#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	
	static int (*orig_connect)(int, const struct sockaddr*, socklen_t) = NULL;
	if(!orig_connect) {
		orig_connect = dlsym(RTLD_NEXT, "connect");
	}

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in new_addr = *(struct sockaddr_in*) addr;

		int org_port = ntohs(new_addr.sin_port);
		
		if (org_port == 443) {
			new_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			new_addr.sin_port = htons(1234);
		} else if (org_port == 80) {
			new_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
			new_addr.sin_port = htons(1233);
		}
		
		
		return orig_connect(sockfd, (struct sockaddr*) &new_addr, sizeof(new_addr));
	}

	return orig_connect(sockfd, addr, addrlen);
}
