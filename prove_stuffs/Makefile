CC = goto-gcc
LD = goto-gcc
GOTOINSTRUMENT = goto-instrument

CFLAGS += -O2
CFLAGS += -std=gnu11
CFLAGS += -Wall
CFLAGS += -Wshadow
CFLAGS += -Wextra
CFLAGS += -Wwrite-strings
CFLAGS += -Wcast-qual
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wmissing-declarations
CFLAGS += -Wpointer-arith
CFLAGS += -Wbad-function-cast
# CFLAGS += -ffunction-sections -fdata-sections

CFLAGS += -I/mnt/ubpf_tools/include -I/home/thomas/Documents/GitHub/ubpf_tools
CFLAGS += -I/mnt/ubpf_tools -I/home/thomas/Documents/GitHub/ubpf_tools/include

# LDFLAGS += -Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now,--gc-sections

LDFLAGS = -lm


SRC = $(shell find .. -type f -name '*.c')

GOTO-OBJ = $(SRC:.c=.gbo)

MAINS = $(SRC:.c=.rel)

GOTO_CHECKS  = --pointer-check
GOTO_CHECKS += --memory-leak-check
GOTO_CHECKS += --bounds-check
GOTO_CHECKS += --div-by-zero-check
GOTO_CHECKS += --signed-overflow-check
GOTO_CHECKS += --pointer-overflow-check
GOTO_CHECKS += --unsigned-overflow-check
GOTO_CHECKS += --conversion-check
GOTO_CHECKS += --undefined-shift-check
GOTO_CHECKS += --float-overflow-check
GOTO_CHECKS += --nan-check
# GOTO_CHECKS += --enum-range-check # too hard to deal with enum range check issue #5808 https://github.com/diffblue/cbmc/pull/5808
GOTO_CHECKS += --pointer-primitive-check
# GOTO_CHECKS += --uninitialized-check   # cbmc failed to generate annotation


all: $(MAINS)

%.gbo: %.c
	@echo GOTO-CC $@
	@$(CC) $(CFLAGS) $(LDFLAGS) -DPROVERS -c -o $@ $<


%.rel: %.gbo
	@echo GOTO-INSTRUMENT $<
	@$(GOTOINSTRUMENT) $< $@ $(GOTO_CHECKS)

#%.rel: %.gbf
#	@echo GOTO-LD $@
#	@$(LD) $(LDFLAGS) $(TARGET_ARCH) $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: clean

clean:
	@echo RM $(GOTO-OBJ) $(MAIN) $(MAIN_INST)
	@rm -f *.gbo *.rel *.inst $(GOTO-OBJ) $(MAIN) $(MAINT_INST)
