# Zakladne nastavenia
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Pre Windows: Cesty k OpenSSL
ifeq ($(OS),Windows_NT)
    LDFLAGS = -L"C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT" -lssl -lcrypto
    CFLAGS += -I"C:/Program Files/OpenSSL-Win64/include"
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

.PHONY: all clean
