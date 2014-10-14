#!/usr/bin/python
# -*- coding: utf-8 -*-

import ipapkcs11
from ipapkcs11 import IPA_PKCS11
import sys

def str_to_hex(s):
    return ''.join("{:02x}".format(ord(c)) for c in s)

if __name__ == '__main__':
    p11 = IPA_PKCS11()
    try:
        p11.initialize(0, "1234", "/usr/lib64/pkcs11/libsofthsm2.so")
        p11.generate_replica_key_pair(u"replica1", "id1", pub_cka_wrap=True,
                                      priv_cka_unwrap=True)
        #sys.exit(0)
        p11.generate_master_key(u"žžž-aest", "m", key_length=16)
        p11.generate_replica_key_pair(u"replica2", "id2", pub_cka_wrap=True, priv_cka_unwrap=True)
        key = p11.get_key_handle(ipapkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica1", cka_wrap=True)
        key_priv = p11.get_key_handle(ipapkcs11.KEY_CLASS_PRIVATE_KEY, label=u"replica1", cka_unwrap=True)
        key2_priv = p11.get_key_handle(ipapkcs11.KEY_CLASS_PRIVATE_KEY, label=u"replica2", cka_unwrap=True)
        key2 = p11.get_key_handle(ipapkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica2", cka_wrap=True)
        print 'key handler', key
        try:
            print 'key handler', p11.get_key_handle(ipapkcs11.KEY_CLASS_PUBLIC_KEY, label=u"replica666")
        except ipapkcs11.NotFound:
            print "OK: NotFound"
        key3 = p11.get_key_handle(ipapkcs11.KEY_CLASS_SECRET_KEY, label=u"žžž-aest", id="m")
        print "Got key ", key3
        #key3_attrs = p11.export_secret_key(key3)
        #print "Export secret key: ", str_to_hex(key3_attrs["value"])
        pub = p11.export_public_key(key)
        print "Public key", str_to_hex(pub)
        f = open("public_key.asn1.der", "wb")
        f.write(pub)
        f.close()
        print 'imported', p11.import_public_key(u'test_import', '1245', pub, 
                                                cka_wrap=True)

        try:
            print "wrapping dnssec priv key by master key"
            wrapped_priv = p11.export_wrapped_key(key2_priv, key3, 
                                              ipapkcs11.MECH_AES_KEY_WRAP_PAD)
            print "wrapped_dnssec priv key:", str_to_hex(wrapped_priv)
            imported_priv = p11.import_wrapped_private_key(u'test_import_wrapped_priv',
                                                      '666',
                                                      wrapped_priv, key3,
                                                      ipapkcs11.MECH_AES_KEY_WRAP_PAD,
                                                      ipapkcs11.KEY_TYPE_RSA)

        except Exception as e:
            print e

        wrapped = p11.export_wrapped_key(key3, key2,
                                         ipapkcs11.MECH_RSA_PKCS
                                         )
        print "wrapped key (secret master wrapped by pub key):", str_to_hex(wrapped)
        print "import wrapped master key (master wrapped with pubkey)", p11.import_wrapped_secret_key(
                        u'test_import_wrapped', '555', wrapped, key2_priv,
                        ipapkcs11.MECH_RSA_PKCS,
                        ipapkcs11.KEY_TYPE_AES
                    )

        p11.set_attribute(key, ipapkcs11.CKA_LABEL, u"newlabelž")
        print "get label", p11.get_attribute(key, ipapkcs11.CKA_LABEL)
        try:
            p11.generate_master_key(u"žžž-aest", "m", key_length=16)
            p11.generate_master_key(u"žžž-aest", "m", key_length=16)
        except ipapkcs11.DuplicationError as e:
            print "OK: duplication:", e
        except Exception as e:
            print "FAIL: ", e
        else:
            print "FAIL: expected error"
        
        try:
            p11.generate_master_key(u"žžž-aest", "m-test", key_length=16)
            p11.get_key_handle(ipapkcs11.KEY_CLASS_SECRET_KEY, label=u"žžž-aest")
        except ipapkcs11.DuplicationError as e:
            print "OK: exception ", e
        except Exception as e:
            print "FAIL", e
        else:
            print "FAIL: exception expected"
            
        try:
            objects = p11.find_keys(ipapkcs11.KEY_CLASS_SECRET_KEY, label=u"žžž-aest")
            print "find: objects=", repr(objects)
        except Exception as e:
            print "FAIL:", e

        print "Delete key ", p11.delete_key(key)
        p11.delete_key(key2_priv)
        p11.delete_key(key3)
    #except ipapkcs11.Exception as e:
    #    print "PKCS11 FAILURE:", e
    #except Exception as e:
    #    print "GLOBAL FAILURE:", e
    finally:
        p11.finalize()
