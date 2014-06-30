CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wbad-function-cast
OPT = -O0 -ggdb3
CFLAGS	= -I/usr/include/p11-kit-1/p11-kit $(OPT) $(W)
LDLIBS	= -ldl
SOLIBS	=

########################################################################

PROGS	= gen_mkey
all:	$(PROGS)

clean:
	rm -rf $(PROGS) *.[ao] *~

gen_mkey: gen_mkey.o library.o

%:	%.o
	$(CC) $(CFLAGS) $(LDLIBS) $^ $(LDLIBS) -o $@

%.o:	%.c common.c library.h library.c
	$(CC) $(CFLAGS) $(LDLIBS) -c $<
