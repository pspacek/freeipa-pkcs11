#include "common.c"

CK_RV
export_secret_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BYTE id[] = {0x01};
    CK_ATTRIBUTE find_template[] = {
         { CKA_CLASS, &keyClass, sizeof(keyClass) },
         { CKA_ID, &id, sizeof(id) }
    };

    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;

    CK_BYTE_PTR value = NULL;
    unsigned int i;

    CK_ATTRIBUTE obj_template[] = {
         {CKA_VALUE, NULL_PTR, 0}
    };

    rv = p11->C_FindObjectsInit(session, find_template, 1);
    check_return_value(rv, "Find objects init");
    rv = p11->C_FindObjects(session, &object, 1, &objectCount);
    check_return_value(rv, "Find first object");

    if (objectCount != 1) {
	    rv = CKR_VENDOR_DEFINED;
	    check_return_value(rv, "Exactly 1 object is expected");
    }

    rv = p11->C_GetAttributeValue(session, object, obj_template, 1);
    check_return_value(rv, "get attribute value - prepare");
    
    /* Set proper size for attributes*/
    value = (CK_UTF8CHAR_PTR) malloc(obj_template[0].ulValueLen * sizeof(CK_BYTE));
    obj_template[0].pValue = value;
    
    rv = p11->C_GetAttributeValue(session, object, obj_template, 1);
    check_return_value(rv, "get attribute value");
    
    fprintf(stdout, "Found a key:\n");
    if (obj_template[0].ulValueLen > 0) {
         fprintf(stdout, "\tvalue: ");
         for(i=0; obj_template[0].ulValueLen>i; ++i) fprintf(stdout, "%02x", value[i]);
         fprintf(stdout, "\n");
    } else {
         fprintf(stderr, "\tvalue too large, or not found\n");
    }
       
    rv = p11->C_FindObjectsFinal(session);
    check_return_value(rv, "Find objects final");
    return CKR_OK;
}


CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return export_secret_key(p11, session);
}
