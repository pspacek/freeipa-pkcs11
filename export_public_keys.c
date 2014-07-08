#include "common.c"

//TODO make function to return only one result and search by label and id
CK_RV
export_public_keys(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE find_template[] = {
         { CKA_CLASS, &keyClass, sizeof(keyClass) }
         //TODO find by id and label
    };

    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;

    CK_UTF8CHAR_PTR label = NULL;
    CK_BYTE_PTR id = NULL;
    CK_BYTE_PTR modulus = NULL;
    CK_BYTE_PTR exponent = NULL;
    unsigned int i;

    CK_ATTRIBUTE obj_template[] = {
         {CKA_LABEL, NULL_PTR, 0},
         {CKA_ID, NULL_PTR, 0},
         {CKA_MODULUS, NULL_PTR, 0},
         {CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
    };

    rv = p11->C_FindObjectsInit(session, find_template, 1);
    check_return_value(rv, "Find objects init");
    rv = p11->C_FindObjects(session, &object, 1, &objectCount);
    check_return_value(rv, "Find first object");

    while (objectCount > 0) {
        rv = p11->C_GetAttributeValue(session, object, obj_template, 4);
        check_return_value(rv, "get attribute value - prepare");

        /* Set proper size for attributes*/
        label = (CK_UTF8CHAR_PTR) malloc(obj_template[0].ulValueLen * sizeof(CK_UTF8CHAR));
        obj_template[0].pValue = label;
        id = (CK_BYTE_PTR) malloc(obj_template[1].ulValueLen * sizeof(CK_BYTE));
        obj_template[1].pValue = id;
        modulus = (CK_BYTE_PTR) malloc(obj_template[2].ulValueLen * sizeof(CK_BYTE));
        obj_template[2].pValue = modulus;
        exponent = (CK_BYTE_PTR) malloc(obj_template[3].ulValueLen * sizeof(CK_BYTE));
        obj_template[3].pValue = exponent;

        rv = p11->C_GetAttributeValue(session, object, obj_template, 4);
        check_return_value(rv, "get attribute value");

        fprintf(stdout, "Found a key:\n");
        if (obj_template[0].ulValueLen > 0) {
             fprintf(stdout, "\tlabel: ");
             for(i=0; obj_template[0].ulValueLen>i; ++i) fprintf(stdout, "%c", label[i]);
             fprintf(stdout, "\n");
        } else {
             fprintf(stderr, "\tid too large, or not found\n");
        }
        if (obj_template[1].ulValueLen > 0) {
             fprintf(stdout, "\tid: ");
             for(i=0; obj_template[1].ulValueLen>i; ++i) fprintf(stdout, "%02x", id[i]);
             fprintf(stdout, "\n");
        } else {
             fprintf(stderr, "\tid too large, or not found\n");
        }
        if (obj_template[2].ulValueLen > 0) {
             fprintf(stdout, "\tmodulus: ");
             for(i=0; obj_template[2].ulValueLen>i; ++i) fprintf(stdout, "%02x", modulus[i]);
             fprintf(stdout, "\n");
        } else {
             fprintf(stderr, "\tmodulus too large, or not found\n");
        }
        if (obj_template[3].ulValueLen > 0) {
             fprintf(stdout, "\texponent: ");
             for(i=0; obj_template[3].ulValueLen>i; ++i) fprintf(stdout, "%02x", exponent[i]);
             fprintf(stdout, "\n");
        } else {
             fprintf(stderr, "\texponent too large, or not found\n");
        }
        
        rv = p11->C_FindObjects(session, &object, 1, &objectCount);
        check_return_value(rv, "Find first object");
        
    }

    rv = p11->C_FindObjectsFinal(session);
    check_return_value(rv, "Find objects final");
    return CKR_OK;
}


CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return export_public_keys(p11, session);
}