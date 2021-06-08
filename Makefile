CC=clang
LLC=llc
SRC=$(shell find . -name '*.c' -not -path "./prove_stuffs/*")
OBJ=$(SRC:.c=.o)
OBJ_PRE_T2=$(SRC:.c=.pre_t2)
OBJ_T2=$(SRC:.c=.t2)
OBJ_LL=$(SRC:.c=.ll)
OBJ_BC=$(SRC:.c=.bc)

CFLAGS = -Wall -Wextra -I$(LIBXBGP)

all: $(SRC) $(OBJ)

%.o: %.c
	@echo eBPF CC $<
	@$(CC) $(CFLAGS) -fno-stack-protector -O2 -emit-llvm -c $< -o - | $(LLC) -O2 -march=bpf -filetype=obj -o $@

clean:
	rm -f $(OBJ) $(OBJ_PRE_T2) $(OBJ_T2) $(OBJ_LL) $(OBJ_BC)

copy: $(OBJ)
	@echo CP eBPF bytecode
	@cp $(OBJ) ~/bird_routing/etc
	@echo CP manifest
	@cp manifest.json ~/bird_routing/etc


.PHONY: all clean copy
