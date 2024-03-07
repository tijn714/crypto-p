CC = gcc
CFLAGS = -Wall -Wextra -Werror -Wpedantic -std=c99

all: aes sha256 stsio

aes: aes.c
    $(CC) $^ -o $@ $(CFLAGS)

sha256: sha256.c
    $(CC) $^ -o $@ $(CFLAGS)

stsio: stsio.c
    $(CC) $^ -o $@ $(CFLAGS)

clean:
    rm -f aes sha256 stsio
