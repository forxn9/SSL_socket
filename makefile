
all:clean
	@gcc ssl_server.c -o ssl_server -lpthread -lssl -lcrypto
	@gcc client.c -o client 
	@gcc ssl.c -o  ssl -lpthread -lssl -lcrypto

clean:
	rm -f ssl_server client ssl
