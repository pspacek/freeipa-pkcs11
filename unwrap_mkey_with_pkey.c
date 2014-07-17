#include "common.c"

CK_RV
unwrap_secret_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_OBJECT_HANDLE replicaKey;
     CK_MECHANISM wrappingMech = {CKM_RSA_PKCS, NULL, 0};
     CK_RV rv;
     CK_BYTE wrappedKey[10240];
     CK_ULONG wrappedKeyLen = 0;

     CK_OBJECT_HANDLE unwrappedKey;
     CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
     CK_BBOOL true = CK_TRUE;
     CK_BBOOL false = CK_FALSE;
     CK_BYTE id[] = {'m'};
     CK_KEY_TYPE keyType = CKK_AES;
     CK_ATTRIBUTE template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) },
          { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
          { CKA_ID, &id, sizeof(id) },
          { CKA_TOKEN, &true, sizeof(true) },
          { CKA_SENSITIVE, &false, sizeof(false) },
          { CKA_EXTRACTABLE, &true, sizeof(true) }
     };

     wrappedKeyLen = fread(wrappedKey, 1, sizeof(wrappedKey), fopen("master-aes6d", "r"));
/*
     if (!feof(stdin)) {
          rv = CKR_BUFFER_TOO_SMALL;
          check_return_value(rv, "input too long");
     }
     */
     replicaKey = find_key(p11, session, CKO_PRIVATE_KEY);
     rv = p11->C_UnwrapKey(session, &wrappingMech, replicaKey, wrappedKey,
    		 	 	 	   wrappedKeyLen, template,
    		 	 	 	   sizeof(template)/sizeof(CK_ATTRIBUTE), &unwrappedKey);
     check_return_value(rv, "key unwrapping");
     return rv;
}

CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     return unwrap_secret_key(p11, session);
}
