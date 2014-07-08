CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wbad-function-cast
OPT = -O0 -ggdb3
CFLAGS	= -I/usr/include/p11-kit-1/p11-kit $(OPT) $(W)
LDLIBS	= -ldl
SOLIBS	=

########################################################################

PROGS	= gen_mkey gen_pkey wrap_mkey_with_pkey export_public_keys
all:	$(PROGS)

clean:
	rm -rf $(PROGS) *.[ao] *~

gen_mkey: gen_mkey.o library.o
gen_pkey: gen_pkey.o library.o
wrap_mkey_with_pkey:	wrap_mkey_with_pkey.o library.o
export_public_keys: export_public_keys.o library.o

%:	%.o
	$(CC) $(CFLAGS) $(LDLIBS) $^ $(LDLIBS) -o $@

%.o:	%.c common.c library.h library.c
	$(CC) $(CFLAGS) $(LDLIBS) -c $<
