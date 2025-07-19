CC = gcc
CFLAGS = -Iinclude -Wall
LDFLAGS = -lssl -lcrypto

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = hashsig

all: $(TARGET)

$(TARGET): $(OBJ) main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

clean:
	rm -f $(TARGET) $(OBJ) main.o bench.csv
