# makefile for netcat, based off same ol' "generic makefile".
# Usually do "make systype" -- if your systype isn't defined, try "generic"
# or something else that most closely matches, see where it goes wrong, fix
# it, and MAIL THE DIFFS back to Hobbit.

### PREDEFINES

# DEFAULTS, possibly overridden by <systype> recursive call:
# pick gcc if you'd rather , and/or do -g instead of -O if debugging
# debugging
# DFLAGS = -DTEST -DDEBUG
#
# WARNING: -DGAPING_SECURITY_HOLE enables the -e flag (execute program after
# connect). This allows running arbitrary commands via encrypted reverse shell.
# Remove this define to build without remote exec capability.
DFLAGS = -DGAPING_SECURITY_HOLE
CFLAGS = -O
XFLAGS =
XLIBS = -lssl -lcrypto -lstdc++ -lz


# -Bstatic for sunos,  -static for gcc, etc.  You want this, trust me.
STATIC =
CC = cc $(CFLAGS)
LD = $(CC) -s	# linker; defaults to stripped executables
o = o		# object extension

ALL = clawsec

### BOGON-CATCHERS

bogus:
	@echo "Usage:  make  <systype>  [options]"

### HARD TARGETS

clawsec:	clawsec.c net.o relay.o exec.o util.o obfs.o mux.o fallback.o fingerprint.o tofu.o pqkem.o ecdhe.o farm9crypt.o aesgcm.o
	$(LD) $(DFLAGS) $(XFLAGS) $(STATIC) -o clawsec clawsec.c net.o relay.o exec.o util.o obfs.o mux.o fallback.o fingerprint.o tofu.o pqkem.o ecdhe.o farm9crypt.o aesgcm.o $(XLIBS)


nc-dos:
	@echo "DOS?!  Maybe someday, but not now"

### SYSTYPES -- in the same order as in generic.h, please

# designed for msc and nmake, but easy to change for your compiler.
# Recursive make may fail if you're short on memory -- u-fix!
# Note special hard-target and "quotes" instead of 'quotes' ...
dos:
	$(MAKE) -e $(ALL)-dos $(MFLAGS) CC="cl /nologo" XLIBS= \
	XFLAGS="/AS -D__MSDOS__ -DMSDOS"  o=obj

ultrix:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DULTRIX'

# you may need XLIBS='-lresolv -l44bsd' if you have BIND 4.9.x
sunos:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DSUNOS' STATIC=-Bstatic \
	XLIBS='-lresolv'

# Pick this one ahead of "solaris" if you actually have the nonshared
# libraries [lib*.a] on your machine.  By default, the Sun twits don't ship
# or install them, forcing you to use shared libs for any network apps.
# Kludged for gcc, which many regard as the only thing available.
solaris-static:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DSYSV=4 -D__svr4__ -DSOLARIS' \
	CC=gcc STATIC=-static XLIBS='-lnsl -lsocket -lresolv'

# the more usual shared-lib version...
solaris:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DSYSV=4 -D__svr4__ -DSOLARIS' \
	CC=gcc STATIC= XLIBS='-lnsl -lsocket -lresolv'

aix:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DAIX'

linux:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DLINUX' \
	XLIBS='-lssl -lcrypto -lutil -lstdc++ -lz' STATIC=

macos:
	make -e $(ALL) $(MFLAGS) \
	XFLAGS='-I/opt/homebrew/opt/openssl@3/include' \
	XLIBS='-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lstdc++ -lz' STATIC=



# irix 5.2, dunno 'bout earlier versions.  If STATIC='-non_shared' doesn't
# work for you, null it out and yell at SGI for their STUPID default
# of apparently not installing /usr/lib/nonshared/*.  Sheesh.
irix:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DIRIX -DSYSV=4 -D__svr4__' \
	STATIC=-non_shared

osf:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DOSF' STATIC=-non_shared

# virtually the same as netbsd/bsd44lite/whatever
freebsd:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DFREEBSD' STATIC=-static \
	XLIBS='-lssl -lcrypto -lstdc++ -lz'

bsdi:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DBSDI' STATIC=-Bstatic

netbsd:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DNETBSD' STATIC=-static \
	XLIBS='-lssl -lcrypto -lstdc++ -lz'
openbsd:
	@echo "use: make netbsd"
# finally got to an hpux box, which turns out to be *really* warped. 
# STATIC here means "linker subprocess gets args '-a archive'" which causes
# /lib/libc.a to be searched ahead of '-a shared', or /lib/libc.sl.
hpux:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DHPUX' STATIC="-Wl,-a,archive"

# unixware from bmc@telebase.com; apparently no static because of the
# same idiotic lack of link libraries
unixware:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DUNIXWARE -DSYSV=4 -D__svr4__' \
	STATIC= XLIBS='-L/usr/lib -lnsl -lsocket -lresolv'

# from Declan Rieb at sandia, for a/ux 3.1.1 [also suggests using gcc]:
aux:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DAUX' STATIC=-static CC=gcc

# Nexstep from mudge: NeXT cc is really old gcc
next:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DNEXT' STATIC=-Bstatic

ecdhe.o: ecdhe.cc ecdhe.h obfs.h tofu.h pqkem.h
		${CC} $(XFLAGS) -c ecdhe.cc

farm9crypt.o: farm9crypt.cc farm9crypt.h ecdhe.h
		${CC} $(XFLAGS) -c farm9crypt.cc

aesgcm.o: aesgcm.cc aesgcm.h
		${CC} $(XFLAGS) -c aesgcm.cc

util.o: util.c util.h farm9crypt.h
		${CC} $(DFLAGS) $(XFLAGS) -c util.c

net.o: net.c net.h util.h
		${CC} $(DFLAGS) $(XFLAGS) -c net.c

relay.o: relay.c relay.h util.h farm9crypt.h obfs.h
		${CC} $(DFLAGS) $(XFLAGS) -c relay.c

exec.o: exec.c exec.h util.h farm9crypt.h
		${CC} $(DFLAGS) $(XFLAGS) -c exec.c

obfs.o: obfs.c obfs.h
		${CC} $(DFLAGS) $(XFLAGS) -c obfs.c

mux.o: mux.c mux.h farm9crypt.h util.h net.h obfs.h relay.h
		${CC} $(DFLAGS) $(XFLAGS) -c mux.c

fallback.o: fallback.c fallback.h obfs.h net.h util.h
		${CC} $(DFLAGS) $(XFLAGS) -c fallback.c

fingerprint.o: fingerprint.c fingerprint.h
		${CC} $(DFLAGS) $(XFLAGS) -c fingerprint.c

tofu.o: tofu.c tofu.h
		${CC} $(DFLAGS) $(XFLAGS) -c tofu.c

pqkem.o: pqkem.c pqkem.h
		${CC} $(DFLAGS) $(XFLAGS) -c pqkem.c


generic:
	make -e $(ALL) $(MFLAGS) XFLAGS='$(XFLAGS) -DGENERIC' \
	XLIBS='$(XLIBS) -lstdc++' STATIC=

alpine:
	make -e $(ALL) $(MFLAGS) XFLAGS='-DLINUX -DGENERIC' \
	XLIBS='-lssl -lcrypto -lutil -lstdc++ -lz' STATIC=


# Still at large: dgux dynix ???

### RANDOM

TESTDIR = ../tests

clean:
	rm -f clawsec cryptcat test_clawsec *.o *.obj

TEST_SRC = $(TESTDIR)/test_clawsec.c $(TESTDIR)/test_crypto.c $(TESTDIR)/test_protocol.c \
	$(TESTDIR)/test_handshake.c $(TESTDIR)/test_obfs.c $(TESTDIR)/test_parse.c \
	$(TESTDIR)/test_zlib.c $(TESTDIR)/test_sha256.c $(TESTDIR)/test_chat.c \
	$(TESTDIR)/test_util.c $(TESTDIR)/test_stealth.c $(TESTDIR)/test_ech.c \
	$(TESTDIR)/test_mux.c $(TESTDIR)/test_fallback.c $(TESTDIR)/test_fingerprint.c \
	$(TESTDIR)/test_tofu.c $(TESTDIR)/test_pqkem.c

test: farm9crypt.o aesgcm.o ecdhe.o obfs.o mux.o fallback.o fingerprint.o tofu.o pqkem.o net.o util.o $(TEST_SRC) $(TESTDIR)/test.h
	$(LD) $(XFLAGS) -I. -I$(TESTDIR) -o test_clawsec $(TEST_SRC) farm9crypt.o aesgcm.o ecdhe.o obfs.o mux.o fallback.o fingerprint.o tofu.o pqkem.o net.o util.o $(XLIBS)
	./test_clawsec

test-macos:
	make -e test \
		XFLAGS='-I/opt/homebrew/opt/openssl@3/include' \
		XLIBS='-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lstdc++ -lz'

