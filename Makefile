# Makefile

TARGETS=	s_client

OPENSSL_SRC=	$(HOME)/src/ssl/openssl-1.0.0f
OPENSSL_INC=	/usr/local/ssl/include
OPENSSL_LIB=	/usr/local/ssl/lib

UNBOUND_INC=	/usr/local/include
UNBOUND_LIB=	/usr/local/lib

CFLAGS=		-I$(OPENSSL_INC) -I$(UNBOUND_INC) -DOPENSSL_NO_PSK -DOPENSSL_DANE
LDFLAGS=	-L$(OPENSSL_LIB) -lssl -lcrypto -L$(UNBOUND_LIB) -lunbound

S_CLIENT_OBJ=	s_client.o s_cb.o s_socket.o apps.o app_rand.o dane.o


all: $(TARGETS)

s_client: $(S_CLIENT_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(S_CLIENT_OBJ)

dane.o: dane.c
	$(CC) -c $(CFLAGS) $<

s_client.o: s_client.c
	$(CC) -c -I$(OPENSSL_SRC) -I$(OPENSSL_SRC)/apps $(CFLAGS) $<

s_cb.o: $(OPENSSL_SRC)/apps/s_cb.c
	$(CC) -c -I$(OPENSSL_SRC) -I$(OPENSSL_SRC)/apps $(CFLAGS) $<

s_socket.o: $(OPENSSL_SRC)/apps/s_socket.c
	$(CC) -c -I$(OPENSSL_SRC) -I$(OPENSSL_SRC)/apps $(CFLAGS) $<

apps.o: $(OPENSSL_SRC)/apps/apps.c
	$(CC) -c -I$(OPENSSL_SRC) -I$(OPENSSL_SRC)/apps $(CFLAGS) $<

app_rand.o: $(OPENSSL_SRC)/apps/app_rand.c
	$(CC) -c -I$(OPENSSL_SRC) -I$(OPENSSL_SRC)/apps $(CFLAGS) $<

diff:
	diff -u $(OPENSSL_SRC)/apps/s_client.c s_client.c

clean:
	rm -f *.o $(TARGETS)
