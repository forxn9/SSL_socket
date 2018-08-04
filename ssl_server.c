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
    int opt = 1;

    if (argv[1])
        myport = atoi(argv[1]);
    else
        myport = 7838;

    if (argv[2])
        lisnum = atoi(argv[2]);
    else
        lisnum = 2;

    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[5], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("socket failure");
        exit(1);
    } 

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);

    if (argv[3])
        my_addr.sin_addr.s_addr = inet_addr(argv[3]);
    else
        my_addr.sin_addr.s_addr = INADDR_ANY;

    setsockopt( sockfd, SOL_SOCKET,SO_REUSEADDR, (const void *)&opt, sizeof(opt) );

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) < 0) 
    {
        perror("bind failure");
        exit(1);
    } 

    if (listen(sockfd, lisnum) < 0) 
    {
        perror("listen failure");
        exit(1);
    }
    
    printf("Start SSL accept\n");

    while (1) 
    {
        SSL *ssl;
        pthread_t tid;
        len = sizeof(struct sockaddr);

        printf("SSL Server start new  accept\n");

        /* 等待客户端连上来 */
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1) 
        {
            perror("accept\n");
            exit(errno);
        } 
        else
        {
            printf("SSL server: got connection from %s, port %d, socket %d\n",
                   inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), new_fd);
        }

        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);
        /* 将连接用户的 socket 加入到 SSL */
        SSL_set_fd(ssl, new_fd);
        /* 建立 SSL 连接 */
        if (SSL_accept(ssl) == -1) {
            perror("accept\n");
            close(new_fd);
            break;
        }
       else
       {
        printf("Start create thread worker\n");
        pthread_create(&tid, NULL,thread_worker, (void *)ssl);
      //  pthread_join(tid, NULL);
       }

      printf("Thread worker create over\n");
    }
    /* 关闭监听的 socket */
    close(sockfd);
       /* 释放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}

void *thread_worker(void *arg) 
{
        char buf[MAXBUF];
        socklen_t len;
        SSL *ssl=(SSL *)arg;
  while(1)
  {
        bzero(buf, MAXBUF );
        len = SSL_read(ssl, buf, MAXBUF);
        buf[strlen(buf)-1]='\0';
        if (len > 0)
        {
            printf("memsage  received successful! total %d bytes data received\n%s\n=======from client=======\n",  len,buf);
        }
        else
        {
            printf ("receive memsage failure！error number %d，error reason:'%s'\n", errno, strerror(errno));
        }

        bzero(buf, MAXBUF );
        printf("please input data to client:\n");
        fgets(buf,MAXBUF, stdin);
        buf[strlen(buf)-1]='\0';
        len = SSL_write(ssl, buf, strlen(buf));
        if (len <= 0) 
        {
            printf
                ("memsage'%s'send failure！error number:%d，error reason:'%s'\n", buf, errno, strerror(errno));
         SSL_shutdown(ssl);
         SSL_free(ssl);
        }
        else
          {     
              printf("memsage send successful! total send %d bytes data!\n %s\n=======to client========\n", len,buf);
          }
   }
}
