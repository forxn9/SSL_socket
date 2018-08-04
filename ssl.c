#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
void ShowCerts (SSL* ssl);
void *thread_worker(void *arg);

int main(int argc, char **argv)
{
     int                     socket_fd,  connect_fd = -1;
     struct sockaddr_in      serv_addr;             
     pthread_t tid;
     int opt = 1;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0 )
    {
        printf("create socket failure: %s\n", strerror(errno));
        return -1;
    }
    printf("socket create fd[%d]\n", socket_fd);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;        
    serv_addr.sin_port = htons(8848);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    setsockopt( socket_fd, SOL_SOCKET,SO_REUSEADDR, (const void *)&opt, sizeof(opt) );//地址复用


    if( bind(socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 )
    {
        printf("create socket failure: %s\n", strerror(errno));
        return -2;
    }
    printf("socket bind ok\n", socket_fd);

    listen(socket_fd, 13); 
    printf("listen fd ok\n", socket_fd);

    while(1)   
    {
        printf("waiting for client's connection......\n", socket_fd);
        connect_fd = accept(socket_fd, NULL, NULL);
        if(connect_fd < 0)
        {
            printf("accept new socket failure: %s\n", strerror(errno));
            return -2;
        }
        printf("accept newfd= %d, start create new worker\n", connect_fd);
        pthread_create (&tid, NULL,thread_worker, (void *)connect_fd);
    } 
    close(socket_fd);
}


void *thread_worker(void *arg)
{
    char                    buf[1024]; 
    int                     cli_fd=(int)arg; 

    int sockfd,len;
    struct sockaddr_in dest;

    SSL_CTX *ctx;//定义两个结构体数据https://www.cnblogs.com/274914765qq/p/4513236.html
    SSL *ssl;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx=SSL_CTX_new(SSLv23_client_method());
    if(ctx==NULL)
    {
        ERR_print_errors_fp(stdout);//  将错误打印到FILE中
        exit(1);
    }   
    //创建socket用于tcp通信
    if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0)
    {
        perror("socket");
        exit(errno);
    }
    printf("socket create ok\n");

    memset(&dest,0,sizeof(struct sockaddr_in));
    dest.sin_family=AF_INET;
    dest.sin_port=htons(7838);//ascii to integer  字符串转化为整形数
    //inet_aton 将字符串IP地址转化为32位的网络序列地址
    if(inet_aton("127.0.0.1",(struct in_addr *)&dest.sin_addr.s_addr)==0)
    {
        printf("error ");
        exit(errno);
    }

    //连接服务器
    printf("socket start connect to SSL server\n");
    if(connect(sockfd,(struct sockaddr*)&dest,sizeof(dest))!=0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("socket server connected\n");

    //基于ctx产生一个新的ssl,建立SSL连接
    ssl=SSL_new(ctx);
    SSL_set_fd(ssl,sockfd);
    if(SSL_connect(ssl)==-1)
        ERR_print_errors_fp(stderr);
    else
    {
        printf("connect with %s encryption\n",SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    printf("SSL connect to server ok\n");

while(1)
  {    
    memset(buf, 0, sizeof(buf));        

    read(cli_fd, buf, sizeof(buf));     
    len=SSL_write(ssl,buf,strlen(buf));
    if(len<0)
         printf("memsage send failure");
    else
         printf("SSL_write successful\n==================>>\n%s\n=================>>\n",buf);
  
    memset(buf,0,sizeof(buf));
    SSL_read(ssl,buf,sizeof(buf));
    
    printf("SSL_read ok\n");
    len=write(cli_fd,buf,len);
    if(len>0) 
      {
        
         printf("write successful\n<<=================\n%s\n<<=================\n",buf);
         memset(buf,0,sizeof(buf));
      }

   }
goto finish;

finish:
     SSL_shutdown(ssl);
     SSL_free(ssl);
     close(sockfd);
     SSL_CTX_free(ctx);
     return 0;
}

void ShowCerts (SSL* ssl)
{
    X509 *cert;
    char *line;

    cert=SSL_get_peer_certificate(ssl);
    if(cert !=NULL){
        printf("数字证书信息：\n");
        line=X509_NAME_oneline(X509_get_subject_name(cert),0,0);
        printf("证书：%s\n",line);
        free(line);
        line=X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
        printf("颁发者：%s\n",line);
        free(line);
        X509_free(cert);
    }else
        printf("无证书信息！\n");
}
