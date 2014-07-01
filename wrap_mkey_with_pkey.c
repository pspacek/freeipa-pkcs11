#include "common.c"

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
