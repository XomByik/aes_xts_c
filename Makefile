CC = gcc
CFLAGS = -g -Wall -Wextra -O2 -fopenmp
LDFLAGS = -lcrypto -lssl -fopenmp

ifeq ($(OS),Windows_NT)
	TARGET = aes_xts.exe
	OBJS = aes_xts.o
	OPENSSL_INCLUDE = "C:\Program Files\OpenSSL-Win64\include"
	OPENSSL_LIBS = "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT"
	CFLAGS += -I$(OPENSSL_INCLUDE)
	LDFLAGS = -L$(OPENSSL_LIBS) -lssl -lcrypto -fopenmp
else
	TARGET = aes_xts
	OBJS = aes_xts.o
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)