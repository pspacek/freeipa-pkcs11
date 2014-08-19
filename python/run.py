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
        p11.generate_replica_key_pair(u"replica2", "id2")
        key = p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica1", cka_wrap=True)
        key_priv = p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PRIVATE_KEY, label=u"replica1", cka_wrap=True)
        key2_priv = p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PRIVATE_KEY, label=u"replica2", cka_wrap=True)
        print 'key handler', key
        try:
            print 'key handler', p11.get_key_handler(ipa_pkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica666")
        except ipa_pkcs11.NotFound:
            print "OK: NotFound"
        key3 = p11.get_key_handler(ipa_pkcs11.KEY_CLASS_SECRET_KEY, label=u"žžž-aest", id="m")
        print "Got key ", key
        key3_attrs = p11.export_secret_key(key3)
        print "Export secret key: ", str_to_hex(key3_attrs["value"])
        pub = p11.export_public_key(key)
        print "Public key", str_to_hex(pub)
        f = open("public_key.asn1.der", "wb")
        f.write(pub)
        f.close()
        print 'imported', p11.import_public_key(u'test_import', '1245', pub, 
                                                {'cka_wrap': False})
        wrapped = p11.export_wrapped_private_key(key3, key, 
            wrapping_mech_type=ipa_pkcs11.MECH_RSA_PKCS_OAEP
        )
        print "wrapped key:", str_to_hex(wrapped)
        f = open("wrapped_key.asn1.der", "wb")
        f.write(wrapped)
        f.close()
        print "import wrapped priv key", p11.import_wrapped_private_key(
            u'test_import_wrapped', '555', wrapped, key_priv, 
            key_type = ipa_pkcs11.KEY_TYPE_RSA
        )
        print "Delete key ", p11.delete_key(key)
        p11.delete_key(key2_priv)
        p11.delete_key(key3)
    finally:
        p11.finalize()
