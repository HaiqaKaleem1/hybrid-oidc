/*
 * cgo_glue.c — compiles the constant-time HMK-1 C core into this Go package.
 *
 * The real sources live in ../../csrc and are also built standalone by
 * csrc/Makefile (self-test + side-channel timing harness). Pulling the same
 * translation units in here means `go test ./...` exercises exactly the code
 * that csrc/ ships — no duplicate implementations.
 */
#include "../../csrc/sha256.c"
#include "../../csrc/hmac_sha256.c"
#include "../../csrc/gf256.c"
#include "../../csrc/linspread.c"
#include "../../csrc/hmk.c"
