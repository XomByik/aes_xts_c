# Zakladne nastavenia
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Pre Windows: Cesty k OpenSSL a nastavenia
ifeq ($(OS),Windows_NT)
	OPENSSL_DIR = "C:/Program Files/OpenSSL-Win64"
	CFLAGS += -I$(OPENSSL_DIR)/include -D_FORTIFY_SOURCE=0 -D_WIN32
	# Upravene flags pre Windows
	LDFLAGS = -L$(OPENSSL_DIR)/lib/VC/x64/MT -lssl -lcrypto -lws2_32 \
				-static-libgcc -static-libstdc++ \
				-Wl,-Bstatic -lstdc++ -lpthread \
				-Wl,-Bdynamic
else
	# Pre Linux: Systemove cesty
	LDFLAGS = -lssl -lcrypto
	CFLAGS += -I/usr/include
endif

# Zdrojove subory
SRC = aes_xts.c
OBJ = $(SRC:.c=.o)
EXECUTABLE = aes_xts

# Detekcia platformy
ifeq ($(OS),Windows_NT)
	EXECUTABLE := $(EXECUTABLE).exe
	RM = del /Q
else
	RM = rm -f
endif

# Hlavny ciel
all: $(EXECUTABLE)

# Linkovanie
$(EXECUTABLE): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Kompilacia
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Vycistenie
clean:
	$(RM) *.o
	$(RM) $(EXECUTABLE)

.PHONY: all clean
	\end{lstlisting}