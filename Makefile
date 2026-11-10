# HMK-1: one command reproduces every claim in README.md and paper/main.pdf.
#
#   make verify    C selftest + all Go claim tests + adversary harness +
#                  the three independent checkers
#   make timing    constant-time comparison and unwrap-spread measurements
#   make asm       disassembly audit target for the C core
#
# Requires: cc, make, go >= 1.22, python3, node.

SHELL := /bin/bash
GO    ?= go

.PHONY: verify c-core go-unit attacks checkers timing asm clean

verify: c-core go-unit attacks checkers
	@echo
	@echo "== all HMK-1 checks passed"

c-core:
	$(MAKE) -C csrc test

go-unit:
	$(GO) test -count=1 ./...

attacks:
	$(GO) run ./attacks

checkers:
	python3 tools/gen_vectors.py
	python3 tools/linspread_check.py
	node tools/check_site_core.js

timing:
	$(MAKE) -C csrc timing
	./csrc/hmk_timing

asm:
	$(MAKE) -C csrc asm

clean:
	$(MAKE) -C csrc clean
