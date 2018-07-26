#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#define MAXBUF 1024

void *thread_worker(void *arg);
int main(int argc, char **argv)
{
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;

    if (argv[1])
        myport = atoi(argv[1]);
    else
        myport = 7838;

    if (argv[2])
        lisnum = atoi(argv[2]);
    else
        lisnum = 2;

    /* SSL ���ʼ�� */
    SSL_library_init();
    /* �������� SSL �㷨 */
    OpenSSL_add_all_algorithms();
    /* �������� SSL ������Ϣ */
    SSL_load_error_strings();
    /* �� SSL V2 �� V3 ��׼���ݷ�ʽ����һ�� SSL_CTX ���� SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* Ҳ������ SSLv2_server_method() �� SSLv3_server_method() ������ʾ V2 �� V3��׼ */
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* �����û�������֤�飬 ��֤���������͸��ͻ��ˡ� ֤��������й�Կ */
    if (SSL_CTX_use_certificate_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* �����û�˽Կ */
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[5], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* ����û�˽Կ�Ƿ���ȷ */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* ����һ�� socket ���� */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created\n");

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    if (argv[3])
        my_addr.sin_addr.s_addr = inet_addr(argv[3]);
    else
        my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
        == -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded\n");

    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen\n");

    while (1) {
        SSL *ssl;
        pthread_t tid;
        len = sizeof(struct sockaddr);
        /* �ȴ��ͻ��������� */
        if ((new_fd =
             accept(sockfd, (struct sockaddr *) &their_addr,
                    &len)) == -1) {
            perror("accept");
            exit(errno);
        } else
            printf("server: got connection from %s, port %d, socket %d\n",
                   inet_ntoa(their_addr.sin_addr),
                   ntohs(their_addr.sin_port), new_fd);

        /* ���� ctx ����һ���µ� SSL */
        ssl = SSL_new(ctx);
        /* �������û��� socket ���뵽 SSL */
        SSL_set_fd(ssl, new_fd);
        /* ���� SSL ���� */
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);
            break;
        }
       else
        pthread_create(&tid, NULL,thread_worker, (void *)ssl);


       /* �ر� SSL ���� */
        SSL_shutdown(ssl);
        /* �ͷ� SSL */
        SSL_free(ssl);
        /* �ر� socket */
        close(new_fd);
    }
    /* �رռ����� socket */
    close(sockfd);
       /* �ͷ� CTX */
    SSL_CTX_free(ctx);
    return 0;
}

void *thread_worker(void *arg) {
        char *buf;
         socklen_t len;
        SSL *ssl=(SSL *)arg;
        bzero(buf, MAXBUF + 1);
        len = SSL_read(ssl, buf, MAXBUF);
        if (len > 0)
            printf("memsage '%s' received successful! total %d bytes data received\n",
                   buf, len);
        else
            printf
                ("receive memsage failure��error number %d��error reason:'%s'\n",
                 errno, strerror(errno));
//������Ϣ
        bzero(buf, MAXBUF + 1);
        printf("please input data to client:\n");
        fgets(buf,MAXBUF+1,stdin);
        buf[strlen(buf)-1]='\0';
        len = SSL_write(ssl, buf, strlen(buf));
        if (len <= 0) {
            printf
                ("memsage'%s'send failure��error number:%d��error reason:'%s'\n",
                 buf, errno, strerror(errno));
        } else
            printf("memsage '%s' send successful��total send %d bytes data��\n",
                   buf, len);
}