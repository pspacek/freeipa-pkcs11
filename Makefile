CC	= gcc
W	= -W -Wall -Wno-unused-parameter -Wbad-function-cast
OPT = -O0 -ggdb3
CFLAGS	= -I/usr/include/p11-kit-1/p11-kit $(OPT) $(W)
ifdef PKCS11LIB
	CFLAGS:=$(CFLAGS) -DPKCS11LIB=\"$(PKCS11LIB)\"
else
	CFLAGS:=$(CFLAGS) -DPKCS11LIB=\"/usr/lib64/softhsm/libsofthsm2.so\"
endif
LDLIBS	= -ldl -lcrypto
SOLIBS	=

########################################################################

PROGS	= gen_mkey gen_pkey wrap_mkey_with_pkey export_public_keys \
	  export_secret_key import_public_key  wrappedprivkey_to_asn1 \
	  asn1_to_wrappedprivkey del_obj

all:	$(PROGS)

clean:
	rm -rf $(PROGS) *.[ao] *~

gen_mkey: gen_mkey.o library.o
gen_pkey: gen_pkey.o library.o
wrap_mkey_with_pkey:	wrap_mkey_with_pkey.o library.o
export_public_keys: export_public_keys.o library.o
export_secret_key: export_secret_key.o library.o
import_public_key: import_public_key.o library.o
wrappedprivkey_to_asn1: wrappedprivkey_to_asn1.o library.o
asn1_to_wrappedprivkey: asn1_to_wrappedprivkey.o library.o
del_obj: del_obj.o library.o

%:	%.o
	$(CC) $(CFLAGS) $(LDLIBS) $^ $(LDLIBS) -o $@

%.o:	%.c common.c library.h library.c
	$(CC) $(CFLAGS) $(LDLIBS) -c $<
