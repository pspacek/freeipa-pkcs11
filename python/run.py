#!/usr/bin/python
# -*- coding: utf-8 -*-

from ipa_pkcs11 import IPA_PKCS11

if __name__ == '__main__':
    p11 = IPA_PKCS11()
    try:
        p11.initialize(0, "1234", "/usr/lib64/softhsm/libsofthsm2.so")
        p11.generate_master_key(u"žžž-aest", "m", key_length=16)
        p11.generate_replica_key_pair(u"replica1", "id1")
    finally:
        p11.finalize()
