CC      := gcc
CFLAGS  := -O0 -no-pie -fno-pie \
           -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
           -fcf-protection=none
LDFLAGS := -no-pie
BIN     := lab

.PHONY: build clean
build: $(BIN)

$(BIN): src/lab.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(BIN) *.o
