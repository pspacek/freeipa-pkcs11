#!/usr/bin/python

from ipa_pkcs11 import IPA_PKCS11

if __name__ == '__main__':
    p11 = IPA_PKCS11()
    try:
        p11.initialize(0, "1234", "/usr/lib64/softhsm/libsofthsm2.so")
        print 'DEBUG: initialized'
    finally:
        p11.finalize()
        print 'DEBUG: finalized'
