CC=clang
LLC=llc
SRC=$(shell find . -name '*.c')
OBJ=$(SRC:.c=.o)

CFLAGS = -Wall -Wextra -I.. -I../../proto/bgp

all: $(SRC) $(OBJ)

%.o: %.c
	@echo eBPF CC $<
	@$(CC) $(CFLAGS) -fno-stack-protector -O2 -emit-llvm -c $< -o - | $(LLC) -O2 -march=bpf -filetype=obj -o $@

clean:
	rm -f $(OBJ)

copy: $(OBJ)
	@echo CP eBPF bytecode
	@cp $(OBJ) ~/bird_routing/etc
	@echo CP manifest
	@cp manifest.json ~/bird_routing/etc


.PHONY: all clean copy