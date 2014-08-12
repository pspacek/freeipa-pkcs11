#!/usr/bin/python
# -*- coding: utf-8 -*-

import ipa_pkcs11
from ipa_pkcs11 import IPA_PKCS11

if __name__ == '__main__':
    p11 = IPA_PKCS11()
    try:
        p11.initialize(0, "1234", "/usr/lib64/softhsm/libsofthsm2.so")
        p11.generate_master_key(u"žžž-aest", "m", key_length=16)
        p11.generate_replica_key_pair(u"replica1", "id1")
        print 'key handler', p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica1", cka_wrap=True)
        try:
            print 'key handler', p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica666")
        except ipa_pkcs11.NotFound:
            print "OK: NotFound"
    finally:
        p11.finalize()
