CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
INCLUDES:= -Iinclude
LIBS    := -lpcap -lcrypto

COMMON_SRC := \
    src/filter.c \
    src/pcap_open.c \
    crypto/aead.c \
    crypto/auth.c \
    crypto/extension.c \
    crypto/profiles.c

COMMON_OBJ := $(COMMON_SRC:.c=.o)

BINS := switch1 send receive ack_receive
TARGETS := $(addprefix build/,$(BINS))

all: $(TARGETS)

build/%: src/%.o $(COMMON_OBJ)
	@mkdir -p build
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(COMMON_OBJ) src/*.o crypto/*.o $(TARGETS)

.PHONY: all clean
