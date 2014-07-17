#include "common.c"

/*
CK_RV
unwrap_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
		 CK_MECHANISM_PTR pWrappingMech, CK_OBJECT_HANDLE wrappingKey,
		 CK_BYTE_PTR pWrappedKey, CK_ULONG wrappedKeyLength,
		 CK_ATTRIBUTE_PTR template, CK_ULONG attributeCount,
		 CK_OBJECT_HANDLE_PTR pUnwrappedKey)
{

}*/

CK_RV
delete_key_id(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_BYTE id[1024];
	CK_ULONG idLen;
	CK_OBJECT_HANDLE obj;
	CK_OBJECT_CLASS class;
	char keyType[1024];

	if (scanf("%4s", keyType) != 1) {
		rv = CKR_ARGUMENTS_BAD;
		check_return_value(rv, "scanf key type: m / pub / priv expected");
	}
	if (!strcasecmp(keyType, "m"))
		class = CKO_SECRET_KEY;
	else if (!strcasecmp(keyType, "pub"))
		class = CKO_PUBLIC_KEY;
	else if (!strcasecmp(keyType, "priv"))
		class = CKO_PRIVATE_KEY;
	else {
		rv = CKR_ARGUMENTS_BAD;
		check_return_value(rv, "key type: m / pub / priv expected");
	}

	idLen = scanf("%s", id);
	/*
	if (!feof(stdin)) {
		rv = CKR_BUFFER_TOO_SMALL;
		check_return_value(rv, "input too long");
	}
	*/
	obj = find_key_id(p11, session, id, idLen, class);
	rv = p11->C_DestroyObject(session, obj);
	check_return_value(rv, "object deletion");
	return rv;
}

CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return delete_key_id(p11, session);
}
