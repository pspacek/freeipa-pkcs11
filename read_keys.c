#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <pkcs11.h>

#include "library.h"


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
                           CKF_SERIAL_SESSION,
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

void
show_key_info(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
     CK_RV rv;
     CK_UTF8CHAR *label = (CK_UTF8CHAR *) malloc(80);
     CK_BYTE *id = (CK_BYTE *) malloc(10);
     size_t label_len;
     char *label_str;

     memset(id, 0, 10);

     CK_ATTRIBUTE template[] = {
          {CKA_LABEL, label, 80},
          {CKA_ID, id, 1}
     };

     rv = p11->C_GetAttributeValue(session, key, template, 2);
     check_return_value(rv, "get attribute value");

     fprintf(stdout, "Found a key:\n");
     label_len = template[0].ulValueLen;
     if (label_len > 0) {
          label_str = malloc(label_len + 1);
          memcpy(label_str, label, label_len);
          label_str[label_len] = '\0';
          fprintf(stdout, "\tKey label: %s\n", label_str);
          free(label_str);
     } else {
          fprintf(stdout, "\tKey label too large, or not found\n");
     }
     if (template[1].ulValueLen > 0) {
          fprintf(stdout, "\tKey ID: %02x\n", id[0]);
     } else {
          fprintf(stdout, "\tKey id too large, or not found\n");
     }

     free(label);
     free(id);
}

void
read_private_keys(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
     CK_ATTRIBUTE template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) }
     };
     CK_ULONG objectCount;
     CK_OBJECT_HANDLE object;

     rv = p11->C_FindObjectsInit(session, template, 1);
     check_return_value(rv, "Find objects init");

     rv = p11->C_FindObjects(session, &object, 1, &objectCount);
     check_return_value(rv, "Find first object");

     while (objectCount > 0) {
          show_key_info(p11, session, object);

          rv = p11->C_FindObjects(session, &object, 1, &objectCount);
          check_return_value(rv, "Find other objects");
     }

     rv = p11->C_FindObjectsFinal(session);
     check_return_value(rv, "Find objects final");
}

int
main(int argc, char **argv)
{
     CK_SLOT_ID slot;
     CK_SESSION_HANDLE session;
     CK_BYTE *userPin = NULL;
     CK_RV rv;
     CK_FUNCTION_LIST_PTR p11;
     void *moduleHandle = NULL;

     if (argc > 1) {
          if (strcmp(argv[1], "null") == 0) {
               userPin = NULL;
          } else {
               userPin = (CK_BYTE *) argv[1];
          }
     }

     if (argc < 2) {
	     return 1;
     }
     // Get a pointer to the function list for PKCS#11 library (argv[2])
     CK_C_GetFunctionList pGetFunctionList = loadLibrary(argv[2], &moduleHandle);
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
     read_private_keys(p11, session);
     logout(p11, session);
     end_session(p11, session);
     finalize(p11);
     return EXIT_SUCCESS;
}

