CFLAGS=-I/usr/local/openssl-3.4.0/include
LDFLAGS=-L/usr/local/openssl-3.4.0/lib64

aes_xts: aes_xts.c
	gcc $(CFLAGS) aes_xts.c -o aes_xts $(LDFLAGS) -lssl -lcrypto
