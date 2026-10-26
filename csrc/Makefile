# HMK-1 C core — constant-time master-key wrap
#
#   make            build static lib + self-test + timing demo
#   make test       run KATs / structural checks
#   make timing     run the side-channel measurement demo
#   make asm        disassemble hmk_unwrap for manual branch inspection
CC      ?= cc
CFLAGS  ?= -O2 -std=gnu11 -Wall -Wextra
OBJS     = sha256.o hmac_sha256.o gf256.o linspread.o hmk.o
BINARIES = hmk_selftest hmk_timing

all: libhmk.a $(BINARIES)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

libhmk.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

hmk_selftest: selftest.c libhmk.a
	$(CC) $(CFLAGS) -o $@ selftest.c libhmk.a

hmk_timing: timing_demo.c libhmk.a
	$(CC) $(CFLAGS) -o $@ timing_demo.c libhmk.a -lm

test: hmk_selftest
	./hmk_selftest

timing: hmk_timing
	./hmk_timing

asm: libhmk.a
	objdump -d --no-show-raw-insn libhmk.a | sed -n '/<hmk_unwrap>:/,/^$$/p'

clean:
	rm -f $(OBJS) libhmk.a $(BINARIES)

.PHONY: all test timing asm clean
