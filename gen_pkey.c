#include "common.c"

CK_RV
create_replica_key_pair(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_HANDLE publicKey, privateKey;
     CK_MECHANISM mechanism = {
          CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
     };
     CK_ULONG modulusBits = 2048;
     CK_BYTE publicExponent[] = { 1, 0, 1 };
     CK_BYTE subject[] = "replica1-keypair";
     CK_BYTE id[] = {0xa1};
     CK_ATTRIBUTE publicKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_WRAP, &true, sizeof(true)},
          {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
          {CKA_PUBLIC_EXPONENT, publicExponent, 3},
     };
     CK_ATTRIBUTE privateKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_PRIVATE, &true, sizeof(true)},
          {CKA_SENSITIVE, &false, sizeof(false)}, // prevents wrapping
          {CKA_UNWRAP, &true, sizeof(true)},
          {CKA_EXTRACTABLE, &true, sizeof(true)},
          {CKA_WRAP_WITH_TRUSTED, &false, sizeof(false)} // prevents wrapping
     };

     rv = p11->C_GenerateKeyPair(session,
                            &mechanism,
                            publicKeyTemplate,
			    sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            privateKeyTemplate,
			    sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            &publicKey,
                            &privateKey);
     check_return_value(rv, "generate key pair");
     return CKR_OK;
}


CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return create_replica_key_pair(p11, session);
}
