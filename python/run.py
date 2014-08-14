#!/usr/bin/python
# -*- coding: utf-8 -*-

import ipa_pkcs11
from ipa_pkcs11 import IPA_PKCS11

def str_to_hex(s):
    return ''.join("{:02x}".format(ord(c)) for c in s)

if __name__ == '__main__':
    p11 = IPA_PKCS11()
    try:
        p11.initialize(0, "1234", "/usr/lib64/softhsm/libsofthsm2.so")
        p11.generate_master_key(u"žžž-aest", "m", key_length=16)
        p11.generate_replica_key_pair(u"replica1", "id1")
        key = p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica1", cka_wrap=True)
        print 'key handler', key
        try:
            print 'key handler', p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica666")
        except ipa_pkcs11.NotFound:
            print "OK: NotFound"
        key2 = p11.get_key_handler(ipa_pkcs11.KEY_CLASS_SECRET_KEY, label=u"žžž-aest", id="m")
        print "Got key ", key
        key2_attrs = p11.export_secret_key(key2)
        print "Export secret key: ", str_to_hex(key2_attrs["value"])
        pub = p11.export_public_key(key)
        print "Public key", str_to_hex(pub)
        f = open("public_key.asn1.der", "w")
        f.write(pub)
        f.close()
        print "Delete key ", p11.delete_key(key)
        print 'imported', p11.import_public_key(u'test_import', '1245', pub)
    finally:
        p11.finalize()
