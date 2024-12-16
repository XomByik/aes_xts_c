# Základné nastavenia
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

# Zdrojové súbory
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

# Hlavný cieľ
all: $(EXECUTABLE)

# Linkovanie
$(EXECUTABLE): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Kompilácia
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Vyčistenie
clean:
	$(RM) *.o

.PHONY: all clean