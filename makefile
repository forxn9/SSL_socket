
all:clean
	@gcc ssl_server.c -o ssl_server -lpthread -lssl
	@gcc client.c -o client 
	@gcc ssl.c -o  ssl -lpthread -lssl

clean:
	rm -f ssl_server client ssl
