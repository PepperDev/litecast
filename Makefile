# litecast — plain C99, static binary, no external dependency libraries.
#
# Targets: all format lint cppcheck lizard loc-check test coverage cov-list
#          report install clean.

CC      ?= gcc
PREFIX  ?= /usr/local
DESTDIR ?=

BIN     := bin/litecast
# Vendored third-party crypto (LTC + LTM) is not litecast production code: it
# is excluded from the build, format, lint, and coverage gates by path.
VENDOR  := src/cast/tls/crypto
# litecast's own sources -- wildcard is depth-limited so the depth-4 vendor
# tree can never creep into SRC/INC.
SRC     := $(wildcard src/*.c src/*/*.c src/*/*/*.c)
INC     := $(wildcard src/*.h src/*/*.h src/*/*/*.h)
OBJ     := $(patsubst src/%.c,obj/%.o,$(SRC))
# Vendored LibTomMath sources: compiled on demand (LTO discards unused
# primitives at link), never touched by format/lint/coverage gates.
LTM_DIR := $(VENDOR)/ltm
LTM_SRC := $(wildcard $(LTM_DIR)/bn_*.c)
LTM_OBJ := $(patsubst $(LTM_DIR)/%.c,obj/crypto/ltm/%.o,$(LTM_SRC))
# Vendored LibTomCrypt sources the TLS crypto seam links (SHA-256,
# ChaCha20, Poly1305, ChaCha20-Poly1305 and their support files) —
# the pruned set Dropbear uses for its own chachapoly transport.
LTC_DIR := $(VENDOR)/ltc
LTC_SRC := \
	$(LTC_DIR)/src/stream/chacha/chacha_crypt.c \
	$(LTC_DIR)/src/stream/chacha/chacha_done.c \
	$(LTC_DIR)/src/stream/chacha/chacha_ivctr32.c \
	$(LTC_DIR)/src/stream/chacha/chacha_ivctr64.c \
	$(LTC_DIR)/src/stream/chacha/chacha_keystream.c \
	$(LTC_DIR)/src/stream/chacha/chacha_setup.c \
	$(LTC_DIR)/src/mac/poly1305/poly1305.c \
	$(LTC_DIR)/src/mac/hmac/hmac_init.c \
	$(LTC_DIR)/src/mac/hmac/hmac_process.c \
	$(LTC_DIR)/src/mac/hmac/hmac_done.c \
	$(LTC_DIR)/src/hashes/sha2/sha256.c \
	$(LTC_DIR)/src/hashes/helper/hash_memory.c \
	$(LTC_DIR)/src/hashes/helper/hash_memory_multi.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_init.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_setiv.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_setiv_rfc7905.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_add_aad.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_encrypt.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_decrypt.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_done.c \
	$(LTC_DIR)/src/encauth/chachapoly/chacha20poly1305_memory.c \
	$(LTC_DIR)/src/misc/burn_stack.c \
	$(LTC_DIR)/src/misc/zeromem.c \
	$(LTC_DIR)/src/misc/mem_neq.c \
	$(LTC_DIR)/src/misc/crypt/crypt_argchk.c \
	$(LTC_DIR)/src/misc/crypt/crypt_hash_descriptor.c \
	$(LTC_DIR)/src/misc/crypt/crypt_hash_is_valid.c \
	$(LTC_DIR)/src/misc/crypt/crypt_find_hash.c \
	$(LTC_DIR)/src/misc/crypt/crypt_register_hash.c
LTC_OBJ := $(patsubst $(LTC_DIR)/%.c,obj/crypto/ltc/%.o,$(LTC_SRC))
TESTS   := $(wildcard tests/*_test.c)
TESTBIN := $(patsubst tests/%_test.c,obj/tests/%_test,$(TESTS))

CFLAGS  := -std=c99 -pedantic -pedantic-errors -O3 -Wall -Wextra -Werror \
           -flto -MMD -MP -Isrc -I$(LTC_DIR) -I$(LTM_DIR) -D_GNU_SOURCE
LDFLAGS := -static -flto

TEST_CFLAGS := -std=c99 -pedantic -pedantic-errors -Wall -Wextra -Werror \
               -Isrc -Itests -I$(LTC_DIR) -I$(LTM_DIR) -O0 -g -fprofile-arcs \
               -ftest-coverage -MMD -MP -DLITECAST_TEST -D_GNU_SOURCE
# Vendored libtomcrypt uses GNU extensions (unnamed struct unions in its
# public headers), so it cannot pass -pedantic-errors. It is third-party and
# excluded from lint/coverage gates by path; drop only the pedantic flag.
LTC_CFLAGS := -std=gnu99 -Wall -Wextra -Werror -O3 -flto -MMD -MP -D_GNU_SOURCE

.PHONY: all format lint cppcheck lizard loc-check test testbins gcov-run \
        coverage cov-list report integration-test install clean

all: $(BIN)

$(BIN): $(OBJ) $(LTM_OBJ) $(LTC_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OBJ) $(LTM_OBJ) $(LTC_OBJ) $(LDFLAGS) -o $@

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# The TLS crypto seam includes libtomcrypt's public headers, which use
# GNU-extensions (unnamed struct unions), so it cannot pass -pedantic-errors.
obj/cast/tls/crypt.o: src/cast/tls/crypt.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS:-pedantic-errors=-Wno-error=pedantic) -c $< -o $@

obj/crypto/ltm/%.o: $(LTM_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(LTM_DIR) -c $< -o $@

obj/crypto/ltc/%.o: $(LTC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(LTC_CFLAGS) -I$(LTC_DIR) -I$(LTM_DIR) -c $< -o $@

-include $(OBJ:.o=.d)
-include $(LTM_OBJ:.o=.d)
-include $(LTC_OBJ:.o=.d)
-include $(wildcard obj/tests/*.d)

format:
	@set -e; \
	for f in $$(find src tests \( -name '*.c' -o -name '*.h' \) \
	           -not -path '$(VENDOR)/*'); do \
		tmp=$$(mktemp); \
		indent -linux -l120 -i2 -nut -o "$$tmp" "$$f"; \
		if cmp -s "$$f" "$$tmp"; then \
			rm -f "$$tmp"; \
		else \
			mv "$$tmp" "$$f"; \
			echo "  formatted $$f"; \
		fi; \
	done

cppcheck:
	@# missingIncludeSystem and checkersReport are cppcheck's own informational
	@# notices (system headers / active-checker census), always emitted under
	@# --check-level=exhaustive; they are not code findings. The scoped
	@# suppression disables only these two ids, never real warnings.
	@# src/buf/* is a standalone API module until the source/HTTP consumers
	@# complete in later sections, so cppcheck reports the exported-but-as-yet-
	@# unconsumed accessors as unusedFunction — suppressed per-path. buffer_compact
	@# and buffer_lowest gained live external callers (src/run/pump.c), so the
	@# staticFunction suppression for this path is dropped.
	@# src/cast/* and src/cast/tls/* are likewise consumed only by the test
	@# harness until the control-channel milestone wires the transports and
	@# the client key-exchange milestone consumes the ECDHE API in.
	@# Vendored crypto (third-party) is scoped out via -i$(VENDOR), not
	@# suppressed (CONTRIBUTING §Cppcheck suppression discipline).
	@# varFuncNullUB in src/cast/tls/*: libtommath's mp_init_multi /
	@# mp_clear_multi are sentinel-terminated variadic APIs, so passing NULL
	@# as the final pointer is their documented call form, not a bug.
	cppcheck --enable=all --check-level=exhaustive --error-exitcode=1 \
		-i$(VENDOR) \
		--suppress=missingIncludeSystem --suppress=checkersReport \
		--suppress=toomanyconfigs \
		--suppress=unusedFunction:src/buf/* \
		--suppress=unusedFunction:src/source/* --suppress=unusedFunction:src/net/* \
		--suppress=staticFunction:src/net/* \
		--suppress=unusedFunction:src/cast/* --suppress=staticFunction:src/cast/* \
		--suppress=unusedFunction:src/cast/tls/* --suppress=staticFunction:src/cast/tls/* \
		--suppress=constParameterCallback:src/cast/framing.c \
		--suppress=varFuncNullUB:src/cast/tls/* \
		--suppress=varFuncNullUB:src/cast/tls.c \
		-Isrc src/

lizard:
	lizard -l cpp -C 6 -L 40 -a 5 -T token_count=150 \
		-x '$(VENDOR)/*' -w src/

loc-check:
	@set -e; rc=0; \
	for f in $$(find src \( -name '*.c' -o -name '*.h' \) \
	           -not -path '$(VENDOR)/*'); do \
		n=$$(wc -l < "$$f"); \
		if [ "$$n" -gt 300 ]; then \
			echo "OVER 300 LOC: $$f ($$n)"; \
			rc=1; \
		fi; \
	done; \
	exit $$rc

lint: format cppcheck lizard loc-check

testbins: $(TESTBIN)

# Coverage-instrumented copies of the crypto seams for the test link (the
# BIN's objects have no -fprofile-arcs, so they cannot feed gcov); pedantic
# relaxed in case of a vendored public header.
obj/tests/crypt.o: src/cast/tls/crypt.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS:-pedantic-errors=-Wno-error=pedantic) -c $< -o $@

obj/tests/rsa.o: src/cast/tls/rsa.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS:-pedantic-errors=-Wno-error=pedantic) -c $< -o $@

obj/tests/%_test: tests/%_test.c $(SRC) $(LTM_OBJ) $(LTC_OBJ) obj/tests/crypt.o obj/tests/rsa.o $(INC)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $< $(LINK_OBJS) $(LTM_OBJ) $(LTC_OBJ) obj/tests/crypt.o obj/tests/rsa.o -o $@

# The BIN link builds obj/cast/conn.o & co. lazily, so the test link would
# silently link a stale object whenever those sources change. Declare the
# linked objects as real prerequisites (no-recipe rule; the pattern rule
# above still supplies the recipe) so each test binary relinks when they move.
HTTP_TEST_LINK := obj/buf/buffer.o obj/buf/cvec.o

# ctrl.c drives the TLS transport, so any test that pulls it in (conn_test
# #includes it; main_test links ctrl.o) also needs the TLS record/handshake
# modules. main_test pulls them via MAIN_TEST_LINK below.
TLS_TEST_LINK := obj/cast/tls/detect.o obj/cast/tls/ecdh.o obj/cast/tls/ecdhe.o \
	obj/cast/tls/finish.o obj/cast/tls/hello.o obj/cast/tls/io.o \
	obj/cast/tls/p256.o obj/cast/tls/record.o obj/cast/tls/record_cipher.o \
	obj/cast/tls/record_inq.o obj/cast/tls/tls_ctrl.o obj/cast/tls.o

# main_test #includes the loop, the connect manager, the CLI and main (they
# have no other test home and need their coverage attributed here); it links
# the buffer/cast/net/source modules as objects (their own tests own that
# coverage). The crypto seams come from obj/tests/crypt.o + obj/tests/rsa.o
# (instrumented), so the plain obj/cast/tls/crypt.o and rsa.o are excluded.
MAIN_TEST_LINK := $(HTTP_TEST_LINK) \
	obj/cast/conn.o obj/cast/ctrl.o obj/cast/framing.o obj/cast/json.o \
	obj/cast/json_get.o obj/cast/launch.o obj/cast/proto.o obj/cast/verb.o \
	$(TLS_TEST_LINK) \
	obj/net/http.o obj/net/http_body.o obj/net/http_head.o obj/net/http_parse.o \
	obj/net/http_serve.o obj/net/mdns.o obj/net/mdns_browse.o \
	obj/net/mdns_name.o obj/net/mdns_sel.o \
	obj/source/source.o obj/source/spool.o

obj/tests/http_test: LINK_OBJS += $(HTTP_TEST_LINK)
obj/tests/http_test: $(HTTP_TEST_LINK)

obj/tests/conn_test: LINK_OBJS += $(TLS_TEST_LINK)
obj/tests/conn_test: $(TLS_TEST_LINK)

obj/tests/ctrl_test: LINK_OBJS += $(TLS_TEST_LINK)
obj/tests/ctrl_test: $(TLS_TEST_LINK)

obj/tests/main_test: LINK_OBJS += $(MAIN_TEST_LINK)
obj/tests/main_test: $(MAIN_TEST_LINK)

test: testbins
	@set -e; cd obj/tests && for t in *_test; do ./$$t; done

gcov-run: test
	@rm -rf obj/gcov; mkdir -p obj/gcov
	@# Linking LTO objects names the coverage notes <bin>-<bin>.gcno (and the
	@# runtime data the same way), not the plain <bin>.gcno gcov would guess
	@# from the executable. Locate whatever notes file the build produced.
	@set -e; for t in $(TESTBIN); do \
		name=`basename "$$t"`; \
		notes="$$t".gcno; \
		[ -f "$$notes" ] || notes="$$t"-"$$name".gcno; \
		gcov -o obj/tests "$$notes"; \
		for f in *.gcov; do \
			[ -f "$$f" ] || continue; \
			cp "$$f" "obj/gcov/$$name-$$f"; \
			rm -f "$$f"; \
		done; \
	done

cov-list: gcov-run
	@awk -f tests/coverage.awk -v gate=80 -v list=1 obj/gcov/*.gcov

coverage: gcov-run
	@awk -f tests/coverage.awk -v gate=80 obj/gcov/*.gcov

report:
	@echo "== lint =="; $(MAKE) lint
	@echo "== coverage =="; $(MAKE) coverage
	@echo "== build =="; $(MAKE) all
	@echo "REPORT OK"

# Optional end-to-end test driving the real binary against a fake Cast device.
# Deliberately NOT part of `make report`/the quality gate.
integration-test: all
	@python3 tests/integration_test.py

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1
	install -m0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/litecast
	install -m0644 man/litecast.1 $(DESTDIR)$(PREFIX)/share/man/man1/litecast.1

clean:
	rm -rf obj bin