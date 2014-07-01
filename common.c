 #define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <pkcs11.h>

#include "library.h"

// compat
#define CKM_AES_KEY_WRAP           (0x1090)


CK_BBOOL true = CK_TRUE;
CK_BBOOL false = CK_FALSE;



void
check_return_value(CK_RV rv, const char *message)
{
        if (rv != CKR_OK) {
                fprintf(stderr, "Error at %s: 0x%x\n",
                        message, (unsigned int)rv);
                exit(EXIT_FAILURE);
        }
}

CK_RV
initialize(CK_FUNCTION_LIST_PTR p11)
{
        return p11->C_Initialize(NULL);
}

CK_SLOT_ID
get_slot(CK_FUNCTION_LIST_PTR p11)
{
     CK_RV rv;
     CK_SLOT_ID slotId;
     CK_ULONG slotCount = 10;
     CK_SLOT_ID *slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);

     rv = p11->C_GetSlotList(CK_TRUE, slotIds, &slotCount);
     check_return_value(rv, "get slot list");

     if (slotCount < 1) {
          fprintf(stderr, "Error; could not find any slots\n");
          exit(1);
     }

     slotId = slotIds[0];
     free(slotIds);
     printf("slot count: %d\n", (int)slotCount);
     return slotId;
}

CK_SESSION_HANDLE
start_session(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotId)
{
     CK_RV rv;
     CK_SESSION_HANDLE session;
     rv = p11->C_OpenSession(slotId,
                        CKF_SERIAL_SESSION | CKF_RW_SESSION,
                        NULL,
                        NULL,
                        &session);
     check_return_value(rv, "open session");
     return session;
}

void
login(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_BYTE *pin)
{
     CK_RV rv;
     if (pin) {
          rv = p11->C_Login(session, CKU_USER, pin, strlen((char *)pin));
          check_return_value(rv, "log in");
     }
}

void
logout(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     rv = p11->C_Logout(session);
     if (rv != CKR_USER_NOT_LOGGED_IN) {
          check_return_value(rv, "log out");
     }
}

void
end_session(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
        CK_RV rv;
        rv = p11->C_CloseSession(session);
        check_return_value(rv, "close session");
}

void
finalize(CK_FUNCTION_LIST_PTR p11)
{
        p11->C_Finalize(NULL);
}

int exit_handler(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session) {
     logout(p11, session);
     end_session(p11, session);
     finalize(p11);
     return EXIT_SUCCESS;
}

CK_RV do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);

int
main(int argc, char **argv)
{
     CK_SLOT_ID slot;
     CK_SESSION_HANDLE session;
     CK_BYTE *userPin = (CK_BYTE *)"1234";
     CK_RV rv;
     CK_FUNCTION_LIST_PTR p11;
     void *moduleHandle = NULL;

     // Get a pointer to the function list for PKCS#11 library (argv[2])
     // CK_C_GetFunctionList pGetFunctionList = loadLibrary("/usr/lib64/softhsm/libsofthsm2.so", &moduleHandle);
     CK_C_GetFunctionList pGetFunctionList = loadLibrary("/home/pspacek/softhsm/v2/git/src/lib/.libs/libsofthsm2.so", &moduleHandle);
     if (!pGetFunctionList)
     {
     	fprintf(stderr, "ERROR: Could not load the library.\n");
	return 2;
     }
     
     // Load the function list
     (*pGetFunctionList)(&p11);
     
     rv = initialize(p11);
     check_return_value(rv, "initialize");
     slot = get_slot(p11);
     session = start_session(p11, slot);
     login(p11, session, userPin);

     rv = do_something(p11, session);
     check_return_value(rv, "do_something");
     return exit_handler(p11, session);
}

CK_OBJECT_HANDLE
find_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session,
	CK_OBJECT_CLASS keyClass)
{
     CK_RV rv;
     CK_ATTRIBUTE template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) }
     };
     CK_ULONG objectCount;
     CK_OBJECT_HANDLE object;

     rv = p11->C_FindObjectsInit(session, template, 1);
     check_return_value(rv, "Find key init");

     rv = p11->C_FindObjects(session, &object, 1, &objectCount);
     check_return_value(rv, "Find first key");

     if (objectCount != 1) {
	     rv = (CKR_VENDOR_DEFINED | 1);
	     check_return_value(rv, "More than 1 key found");
     }

     rv = p11->C_FindObjectsFinal(session);
     check_return_value(rv, "Find objects final");
     return object;
}


FILE *
get_key_file(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
     CK_RV rv;
     unsigned int i;
     char *file_name = NULL;
     size_t file_name_len = 1; // for \0
     CK_UTF8CHAR label[80];
     CK_BYTE id[10];
     memset(id, 0, sizeof(id));
     memset(id, 0, sizeof(label));

     CK_ATTRIBUTE template[] = {
          {CKA_LABEL, label, sizeof(label) - 1},
          {CKA_ID, id, sizeof(id) - 1}
     };

     rv = p11->C_GetAttributeValue(session, key, template,
				   sizeof(template)/sizeof(CK_ATTRIBUTE));
     check_return_value(rv, "get attribute value");

     file_name_len += template[0].ulValueLen;
     file_name_len += template[1].ulValueLen*2; // byte -> hex
     file_name = malloc(file_name_len);
     if (file_name == NULL) {
	     rv = CKR_HOST_MEMORY;
	     check_return_value(rv, "key wrapping: file name buffer allocation");
     }
     memcpy(file_name, label, template[0].ulValueLen);
     for (i = 0; i < template[1].ulValueLen; i++) {
	     sprintf(file_name + template[0].ulValueLen + i*2, "%02x", id[i]);
     }
     file_name[file_name_len - 1] = '\0';

     fprintf(stdout, "\tKey label-id: %s\n", file_name);
     return fopen(file_name, "w");
}

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
