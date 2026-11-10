# HMK-1: one command reproduces every claim in README.md and paper/main.pdf.
#
#   make verify    C selftest + all Go claim tests + adversary harness +
#                  the three independent checkers + cross-implementation KAT
#                  + the paper's numbers
#   make kat       check the C core against the independent Python reference
#   make paper     regenerate those numbers, then compile paper/main.pdf
#   make timing    constant-time comparison and unwrap-spread measurements
#   make asm       disassembly audit target for the C core
#
# Requires: cc, make, go >= 1.27, python3, node (paper: tectonic or TeX Live).

SHELL := /bin/bash
GO    ?= go

.PHONY: verify c-core go-unit attacks checkers kat numbers paper timing asm clean

verify: c-core go-unit attacks checkers kat numbers
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

# The committed vectors come from reference/hmk_ref.py, never from the C core;
# kat_test.go drives the production cgo path against them.
kat:
	python3 reference/hmk_ref.py
	python3 tools/gen_kat.py --check

numbers:
	python3 tools/gen_results.py

paper:
	python3 tools/gen_results.py
	cd paper && ./build.sh

timing:
	$(MAKE) -C csrc timing
	./csrc/hmk_timing

asm:
	$(MAKE) -C csrc asm

clean:
	$(MAKE) -C csrc clean
