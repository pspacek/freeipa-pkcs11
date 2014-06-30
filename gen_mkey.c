#include "common.c"

CK_RV
create_master_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_HANDLE symKey;
     CK_MECHANISM mechanism = {
          CKM_AES_KEY_GEN, NULL_PTR, 0
     };
     CK_BYTE subject[] = "master-aes";
     CK_BYTE id[] = {0x01};
     CK_ULONG keyLength = 16;
     CK_ATTRIBUTE symKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_PRIVATE, &true, sizeof(true)},
          {CKA_ENCRYPT, &false, sizeof(false)},
          {CKA_DECRYPT, &false, sizeof(false)},
          {CKA_VERIFY, &false, sizeof(false)},
          {CKA_WRAP, &true, sizeof(true)},
          {CKA_UNWRAP, &true, sizeof(true)},
          {CKA_EXTRACTABLE, &true, sizeof(true)},
          {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)}
     };

     rv = p11->C_GenerateKey(session,
                            &mechanism,
                            symKeyTemplate,
			    sizeof(symKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            &symKey);
     check_return_value(rv, "generate master key");
     return CKR_OK;
}

CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return create_master_key(p11, session);
}
