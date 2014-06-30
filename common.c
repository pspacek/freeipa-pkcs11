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

int do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);

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
     CK_C_GetFunctionList pGetFunctionList = loadLibrary("/usr/lib64/softhsm/libsofthsm2.so", &moduleHandle);
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

