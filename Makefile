CC := gcc

CFLAGS = -Iinclude -Wall -Wextra -MMD -Werror

OUT := build

BIN = $(OUT)/gdbstub_ck804
LIBGDBSTUB = $(OUT)/libgdbstub.a
SHELL_HACK := $(shell mkdir -p $(OUT))
UNAME_S := $(shell uname -s)

LIBSRCS = $(shell find ./lib -name '*.c')
_LIB_OBJ =  $(notdir $(LIBSRCS))
LIB_OBJ = $(_LIB_OBJ:%.c=$(OUT)/%.o)

CSRCS = $(shell find ./src -name '*.c')
_COBJ =  $(notdir $(CSRCS))
COBJ = $(_COBJ:%.c=$(OUT)/%.o)

vpath %.c $(sort $(dir $(CSRCS)))
vpath %.c $(sort $(dir $(LIBSRCS)))

.PHONY: all debug lib clean

all: CFLAGS += -O3
all: LDFLAGS += -O3
all: $(BIN)
lib: $(LIBGDBSTUB)

debug: CFLAGS += -O3 -g -DDEBUG
debug: LDFLAGS += -O3
debug: $(BIN)

$(OUT)/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(LIBGDBSTUB): $(LIB_OBJ)
	$(AR) -rcs $@ $^

$(BIN): $(LIBGDBSTUB) $(COBJ)
ifneq ($(filter MINGW32%,$(UNAME_S)),)
	$(CC) $^ -o $@ $(LDFLAGS) -lgdbstub -L$(OUT) -lwsock32
else
	$(CC) $^ -o $@ $(LDFLAGS) -lgdbstub -L$(OUT)
endif

clean:
	$(RM) $(LIB_OBJ)
	$(RM) $(LIBGDBSTUB)
	$(RM) $(OUT)/*.d
	$(RM) $(COBJ)
	$(RM) $(BIN)

-include $(OUT)/*.d