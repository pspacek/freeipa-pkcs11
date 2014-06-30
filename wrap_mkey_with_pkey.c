#include "common.c"

CK_RV
wrap_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_MECHANISM wrappingMech, CK_OBJECT_HANDLE toBeWrappedKey, CK_OBJECT_HANDLE wrappingKey)
{
     CK_RV rv;
     CK_BYTE_PTR pWrappedKey = NULL;
     CK_ULONG wrappedKeyLen = 0;
     FILE * fp = NULL;

     rv = p11->C_WrapKey(session, &wrappingMech, wrappingKey, toBeWrappedKey, NULL, &wrappedKeyLen);
     check_return_value(rv, "key wrapping: get buffer length");
     pWrappedKey = malloc(wrappedKeyLen);
     if (pWrappedKey == NULL) {
             rv = CKR_HOST_MEMORY;
             check_return_value(rv, "key wrapping: buffer allocation");
     }
     rv = p11->C_WrapKey(session, &wrappingMech, wrappingKey, toBeWrappedKey, pWrappedKey, &wrappedKeyLen);
     check_return_value(rv, "key wrapping: real wrapping");
     fp = get_key_file(p11, session, toBeWrappedKey);
     fwrite(pWrappedKey, wrappedKeyLen, 1, fp);
     fclose(fp);

     return CKR_OK;
}

CK_RV
wrap_secret_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_OBJECT_HANDLE secretKey;
     CK_OBJECT_HANDLE replicaKey;
     CK_MECHANISM wrappingMech = {CKM_RSA_PKCS, NULL, 0};

     secretKey = find_key(p11, session, CKO_SECRET_KEY);
     replicaKey = find_key(p11, session, CKO_PUBLIC_KEY);

     return wrap_key(p11, session, wrappingMech, secretKey, replicaKey);
}

CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     return wrap_secret_key(p11, session);
}
