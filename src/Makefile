# ClawSec Makefile
#
#   make linux     Linux (glibc), system OpenSSL 3 / libargon2 / zlib
#   make alpine    Alpine Linux (musl)
#   make static    Alpine Linux: fully static binary (runs on any Linux; needs
#                  openssl-libs-static argon2-static zlib-static)
#   make macos     macOS with Homebrew (Apple Silicon and Intel)
#   make freebsd   FreeBSD (packages in /usr/local), static
#   make netbsd    NetBSD (pkgsrc in /usr/pkg), static
#   make generic   any POSIX system; pass XFLAGS/XLIBS for include/lib paths
#
#   make test / test-macos / test-asan / fuzz / e2e / e2e-vpn / werror / clean
#
# Optional:
#   DFLAGS=-DGAPING_SECURITY_HOLE   build -e (run a program per connection;
#                                   anyone with the password gets it)
#
# Only POSIX make features are used (suffix rules, no pattern rules), so the
# file works with GNU make and BSD make.

CC       = cc
CFLAGS   = -O2 -g
WARN     = -Wall -Wextra
# Hardening: FORTIFY, stack protector, position-independent code
HARDEN   = -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDHARDEN =
DFLAGS   =
XFLAGS   =
XLIBS    = -lssl -lcrypto -largon2 -lstdc++ -lz
STATIC   =
STRIP    = -s

COMPILE  = $(CC) $(CFLAGS) $(WARN) $(HARDEN) $(DFLAGS) $(XFLAGS)

OBJS = net.o relay.o exec.o util.o obfs.o mux.o fallback.o fingerprint.o \
       tofu.o pqkem.o ecdhe.o argon2kdf.o portscan.o socks5.o filetx.o \
       reverse.o persistent.o tun.o acl.o secret.o farm9crypt.o aesgcm.o

# Objects the unit tests link against (the tests provide main() and globals)
TEST_OBJS = farm9crypt.o aesgcm.o ecdhe.o argon2kdf.o obfs.o mux.o fallback.o \
            fingerprint.o tofu.o pqkem.o net.o util.o portscan.o socks5.o \
            filetx.o reverse.o persistent.o tun.o acl.o secret.o

HEADERS = acl.h aesgcm.h argon2kdf.h ecdhe.h exec.h fallback.h farm9crypt.h \
          filetx.h fingerprint.h mux.h net.h obfs.h persistent.h pqkem.h \
          portscan.h relay.h reverse.h secret.h socks5.h tofu.h tun.h util.h \
          version.h

TESTDIR  = ../tests
TEST_SRC = $(TESTDIR)/test_clawsec.c $(TESTDIR)/test_crypto.c $(TESTDIR)/test_protocol.c \
	$(TESTDIR)/test_handshake.c $(TESTDIR)/test_security.c $(TESTDIR)/test_obfs.c $(TESTDIR)/test_parse.c \
	$(TESTDIR)/test_chat.c \
	$(TESTDIR)/test_util.c $(TESTDIR)/test_stealth.c $(TESTDIR)/test_ech.c \
	$(TESTDIR)/test_mux.c $(TESTDIR)/test_fallback.c $(TESTDIR)/test_fingerprint.c \
	$(TESTDIR)/test_tofu.c $(TESTDIR)/test_pqkem.c $(TESTDIR)/test_argon2.c \
	$(TESTDIR)/test_portscan.c $(TESTDIR)/test_socks5.c $(TESTDIR)/test_filetx.c \
	$(TESTDIR)/test_reverse.c $(TESTDIR)/test_tun.c $(TESTDIR)/test_hardening.c

.SUFFIXES: .c .cc .o

.c.o:
	$(COMPILE) -c $<

.cc.o:
	$(COMPILE) -c $<

usage:
	@echo "Usage: make <linux|alpine|static|macos|freebsd|netbsd|generic> [DFLAGS=-DGAPING_SECURITY_HOLE]"
	@echo "       make test | test-macos | test-asan | e2e | e2e-vpn | werror | clean"

clawsec: clawsec.c $(OBJS) $(HEADERS)
	$(COMPILE) $(STATIC) $(LDHARDEN) $(STRIP) -o clawsec clawsec.c $(OBJS) $(XLIBS)

$(OBJS): $(HEADERS)

# ── Platforms ────────────────────────────────────────────────────────────

linux:
	$(MAKE) -e clawsec XFLAGS='-DLINUX' \
		XLIBS='-lssl -lcrypto -largon2 -lutil -lstdc++ -lz' \
		LDHARDEN='-pie -Wl,-z,relro,-z,now'

alpine:
	$(MAKE) -e clawsec XFLAGS='-DLINUX -DGENERIC' \
		XLIBS='-lssl -lcrypto -largon2 -lutil -lstdc++ -lz' \
		LDHARDEN='-pie -Wl,-z,relro,-z,now'

static:
	$(MAKE) alpine STATIC=-static

# Homebrew lives in /opt/homebrew (Apple Silicon) or /usr/local (Intel)
macos:
	BREW=$$(brew --prefix 2>/dev/null || echo /opt/homebrew); \
	$(MAKE) -e clawsec \
		XFLAGS="-I$$BREW/opt/openssl@3/include -I$$BREW/opt/argon2/include" \
		XLIBS="-L$$BREW/opt/openssl@3/lib -L$$BREW/opt/argon2/lib -lssl -lcrypto -largon2 -lstdc++ -lz"

freebsd:
	$(MAKE) -e clawsec XFLAGS='-DFREEBSD -I/usr/local/include' STATIC=-static HARDEN= \
		XLIBS='-L/usr/local/lib -lssl -lcrypto -largon2 -lpthread -lstdc++ -lz'

netbsd:
	$(MAKE) -e clawsec XFLAGS='-DNETBSD -I/usr/pkg/include' STATIC=-static HARDEN= \
		XLIBS='-L/usr/pkg/lib -lssl -lcrypto -largon2 -lpthread -lstdc++ -lz'

openbsd:
	@echo "OpenBSD ships LibreSSL; install OpenSSL 3 and argon2 from ports, then:"
	@echo "  make generic XFLAGS='-I/usr/local/include/eopenssl30 -I/usr/local/include' \\"
	@echo "       XLIBS='-L/usr/local/lib/eopenssl30 -L/usr/local/lib -lssl -lcrypto -largon2 -lstdc++ -lz'"

generic:
	$(MAKE) -e clawsec XFLAGS='$(XFLAGS) -DGENERIC'

# Fails on any compiler warning (CI)
werror:
	$(MAKE) clean
	$(MAKE) linux WARN='-Wall -Wextra -Werror'
	$(MAKE) test WARN='-Wall -Wextra -Werror'

# ── Tests ────────────────────────────────────────────────────────────────

test: $(TEST_OBJS) $(TEST_SRC) $(TESTDIR)/test.h
	$(CC) $(CFLAGS) $(WARN) $(XFLAGS) -I. -I$(TESTDIR) -o test_clawsec $(TEST_SRC) $(TEST_OBJS) $(XLIBS)
	./test_clawsec

test-macos:
	BREW=$$(brew --prefix 2>/dev/null || echo /opt/homebrew); \
	$(MAKE) -e test \
		XFLAGS="-I$$BREW/opt/openssl@3/include -I$$BREW/opt/argon2/include" \
		XLIBS="-L$$BREW/opt/openssl@3/lib -L$$BREW/opt/argon2/lib -lssl -lcrypto -largon2 -lstdc++ -lz"

# Unit tests under AddressSanitizer (incl. LeakSanitizer) + UBSan (Linux)
test-asan:
	$(MAKE) clean
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(MAKE) -e test HARDEN= CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer'

# libFuzzer harnesses (needs clang): the record layer and all parsers,
# under ASan + UBSan. FUZZ_SECONDS per harness; the corpus is kept in
# fuzz-corpus/ between runs.
FUZZ_SECONDS = 60
FUZZ_FLAGS   = -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
fuzz:
	$(MAKE) clean
	$(MAKE) -e $(TEST_OBJS) CC=clang HARDEN= XFLAGS=-DLINUX \
		CFLAGS='$(FUZZ_FLAGS) -fsanitize=fuzzer-no-link'
	clang $(FUZZ_FLAGS) -fsanitize=fuzzer -I. -I$(TESTDIR)/fuzz -o fuzz_frame \
		$(TESTDIR)/fuzz/fuzz_frame.c $(TEST_OBJS) $(XLIBS)
	clang $(FUZZ_FLAGS) -fsanitize=fuzzer -I. -I$(TESTDIR)/fuzz -o fuzz_parsers \
		$(TESTDIR)/fuzz/fuzz_parsers.c $(TEST_OBJS) $(XLIBS)
	mkdir -p fuzz-corpus/frame fuzz-corpus/parsers
	UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=detect_leaks=1 \
		./fuzz_frame -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1 fuzz-corpus/frame
	UBSAN_OPTIONS=halt_on_error=1 ASAN_OPTIONS=detect_leaks=1 \
		./fuzz_parsers -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1 fuzz-corpus/parsers

# End-to-end tests against the built ./clawsec binary (Linux)
e2e:
	bash $(TESTDIR)/e2e.sh ./clawsec

# VPN end-to-end tests (Linux, root: run as `sudo make e2e-vpn`)
e2e-vpn:
	bash $(TESTDIR)/e2e_vpn.sh ./clawsec

clean:
	rm -f clawsec test_clawsec fuzz_frame fuzz_parsers *.o
