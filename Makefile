# Makefile for XMSS minimal hash-signature in C

CC = gcc
CFLAGS = -Iinclude -I/mingw64/include -Wall
LDFLAGS = -L/mingw64/lib -lssl -lcrypto

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = hashsig

all: $(TARGET)

$(TARGET): $(SRC) main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJ)
