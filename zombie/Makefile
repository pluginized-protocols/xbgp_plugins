MAKEFLAGS += --no-builtin-rules

CC=clang
LLC=llc

CFLAGS += -O2
CFLAGS += -Wall
CFLAGS += -Wshadow
CFLAGS += -Wextra
CFLAGS += -Wwrite-strings
CFLAGS += -Wcast-qual
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wmissing-declarations
CFLAGS += -Wpointer-arith
CFLAGS += -Wbad-function-cast
CFLAGS += -fno-stack-protector


SRC = iterate_rib.c
SRC += decode_msg.c
OBJ=$(SRC:.c=.o)

all: $(OBJ)

%.c:

%.bc: %.c
	@echo LLVM_CC $<
	@$(CC) $(CFLAGS) -emit-llvm -c $< -o $@

%.o: %.bc
	@echo LLC $<
	@$(LLC) -O2 -march=bpf -filetype=obj -o $@ $<


clean:
	@echo RM $(OBJ)
	@rm -f $(OBJ)
	@rm -f *.ll *.pre_t2 *.t2 *.bc

zip: all
	@echo Creating archive...
	tar cf ready.tar.xz $(OBJ) *.plugin *.meta


.PHONY: all clean zip
