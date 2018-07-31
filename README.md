三个c文件能够实现普通socket到ssl加密socket的转化。
文件里有三个c文件，两个脚本文件，一个makefile。
client.c       为普通客户端程序；
ssl.c          为普通socket到ssl_socket的转化器程序；
ssl_server.c   为ssl加密服务端程序；
make_key.sh    为制作证书和私钥的脚本；
run_server.sh  为ssl_server服务端的执行脚本；
注意：ssl.c编译时会出现两个警告，并不影响程序执行，还没找到解决办法。

