CC = gcc
CFLAGS = -Wall -O3 -pthread
TARGET = mc-vanitygen
SRCS = main.c ed25519/ge.c ed25519/keypair.c ed25519/fe.c ed25519/sha512.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -Ied25519 $(SRCS) -o $(TARGET)

clean:
	rm -f $(TARGET)
