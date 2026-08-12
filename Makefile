CC      := gcc
CFLAGS  := -O0 -no-pie -fno-pie \
           -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
           -fcf-protection=none
LDFLAGS := -no-pie
BIN     := target
SRC     ?= target.c

.PHONY: build clean
build: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(BIN) *.o
