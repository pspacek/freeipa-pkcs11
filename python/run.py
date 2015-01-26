#!/usr/bin/python
# -*- coding: utf-8 -*-

from binascii import hexlify
import os
import os.path
import logging
import _ipap11helper
from _ipap11helper import P11_Helper
import sys
import subprocess

def str_to_hex(s):
    return ''.join("{:02x}".format(ord(c)) for c in s)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('t')

    # init token before the test
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    os.environ['SOFTHSM2_CONF']=os.path.join(script_dir, 'tokens', 'softhsm2.conf')
    os.chdir(script_dir)
    subprocess.check_call(['softhsm2-util', '--init-token', '--slot', '0', '--label', 'test', '--pin', '1234', '--so-pin', '1234'])

    p11 = P11_Helper(0, "1234", "/usr/lib64/pkcs11/libsofthsm2.so")

    # master key
    p11.generate_master_key(u"žžž-aest", "m", key_length=16, cka_wrap=True,
            cka_unwrap=True)

    # replica 1
    p11.generate_replica_key_pair(u"replica1", "id1", pub_cka_wrap=True,
                                  priv_cka_unwrap=True)
    rep1_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY, label=u"replica1", cka_wrap=True)
    assert len(rep1_pub) == 1, "replica key pair has to contain 1 pub key instead of %s" % len(rep1_pub)
    rep1_pub = p11.find_keys(uri="pkcs11:object=replica1;objecttype=public")
    assert len(rep1_pub) == 1, "replica key pair has to contain 1 pub key instead of %s" % len(rep1_pub)
    rep1_pub = rep1_pub[0]
    iswrap = p11.get_attribute(rep1_pub, _ipap11helper.CKA_WRAP)
    assert (iswrap is True), "replica public key has to have CKA_WRAP = TRUE"

    rep1_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY, label=u"replica1", cka_unwrap=True)
    assert len(rep1_priv) == 1, "replica key pair has to contain 1 private key instead of %s" % len(rep1_priv)
    rep1_priv = rep1_priv[0]

    # replica 2
    p11.generate_replica_key_pair(u"replica2", "id2", pub_cka_wrap=True, priv_cka_unwrap=True, priv_cka_extractable=True)
    rep2_priv = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY, label=u"replica2", cka_unwrap=True)[0]
    rep2_pub = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY, label=u"replica2", cka_wrap=True)[0]

    test_list = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY, label=u"replica666")
    assert len(test_list) == 0, "list should be empty because label replica666 should not exist"

    # master key
    key3 = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY, label=u"žžž-aest", id="m")[0]
    log.debug("Got master key %s", key3)
    #key3_attrs = p11.export_secret_key(key3)
    #print "Export secret key: ", str_to_hex(key3_attrs["value"])

    pub = p11.export_public_key(rep1_pub)
    log.debug("Exported public key %s", str_to_hex(pub))
    f = open("public_key.asn1.der", "wb")
    f.write(pub)
    f.close()

    rep1_pub_import = p11.import_public_key(u'replica1-import', 'replica1-import-id', pub, 
                                    cka_wrap=True)
    log.debug('imported replica 1 public key: %s', rep1_pub_import)

    # test public key import
    rep1_modulus_orig = p11.get_attribute(rep1_pub, _ipap11helper.CKA_MODULUS)
    rep1_modulus_import = p11.get_attribute(rep1_pub_import, _ipap11helper.CKA_MODULUS)
    log.debug('rep1_modulus_orig   = 0x%s', hexlify(rep1_modulus_orig))
    log.debug('rep1_modulus_import = 0x%s', hexlify(rep1_modulus_import))
    assert rep1_modulus_import == rep1_modulus_orig

    rep1_pub_exp_orig = p11.get_attribute(rep1_pub, _ipap11helper.CKA_PUBLIC_EXPONENT)
    rep1_pub_exp_import = p11.get_attribute(rep1_pub_import, _ipap11helper.CKA_PUBLIC_EXPONENT)
    log.debug('rep1_pub_exp_orig   = 0x%s', hexlify(rep1_pub_exp_orig))
    log.debug('rep1_pub_exp_import = 0x%s', hexlify(rep1_pub_exp_import))
    assert rep1_pub_exp_import == rep1_pub_exp_orig


    log.debug("wrapping dnssec priv key by master key")
    wrapped_priv = p11.export_wrapped_key(rep2_priv, key3, 
                                      _ipap11helper.MECH_AES_KEY_WRAP_PAD)
    log.debug("wrapped_dnssec priv key: %s", str_to_hex(wrapped_priv))
    f = open("wrapped_priv.der", "wb")
    f.write(wrapped_priv)
    f.close()

    imported_priv = p11.import_wrapped_private_key(u'test_import_wrapped_priv',
                                              '666',
                                              wrapped_priv, key3,
                                              _ipap11helper.MECH_AES_KEY_WRAP_PAD,
                                              _ipap11helper.KEY_TYPE_RSA)


    wrapped = p11.export_wrapped_key(key3, rep2_pub,
                                     _ipap11helper.MECH_RSA_PKCS
                                     )
    log.debug("wrapped key (secret master wrapped by pub key): %s", str_to_hex(wrapped))
    log.debug("import wrapped master key (master wrapped with pubkey): %s", p11.import_wrapped_secret_key(
                    u'test_import_wrapped', '555', wrapped, rep2_priv,
                    _ipap11helper.MECH_RSA_PKCS,
                    _ipap11helper.KEY_TYPE_AES
                ))

    p11.set_attribute(rep1_pub, _ipap11helper.CKA_LABEL, u"newlabelž")
    log.debug("get label: %s", p11.get_attribute(rep1_pub, _ipap11helper.CKA_LABEL))
    try:
        p11.generate_master_key(u"žžž-aest", "m", key_length=16)
        p11.generate_master_key(u"žžž-aest", "m", key_length=16)
    except _ipap11helper.DuplicationError as e:
        log.debug("OK: duplication: %s", e)
    else:
        raise AssertionError("FAIL: _ipap11helper.DuplicationError expected")

    objects = p11.find_keys(_ipap11helper.KEY_CLASS_SECRET_KEY, label=u"žžž-aest")
    log.debug("find: objects=%s", repr(objects))

    log.debug("Delete key %s", p11.delete_key(rep1_pub))
    p11.delete_key(rep2_priv)
    p11.delete_key(key3)
    #except _ipap11helper.Exception as e:
    #    print "PKCS11 FAILURE:", e
    #except Exception as e:
    #    print "GLOBAL FAILURE:", e
    #finally:
    #    p11.finalize()
