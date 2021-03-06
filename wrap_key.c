/*
 * Copyright (C) 2014  Red Hat
 * Author: Petr Spacek <pspacek@redhat.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * This code is based on PKCS#11 code snippets from NLnetLabs:
 * http://www.nlnetlabs.nl/publications/hsm/examples/pkcs11/
 * Original license follows:
 */

/*
 * Copyright (c) 2008, NLnet Labs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *   - Neither the name of NLnet Labs nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

CK_OBJECT_HANDLE
find_master_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
     CK_ATTRIBUTE template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) }
     };
     CK_ULONG objectCount;
     CK_OBJECT_HANDLE object;

     rv = p11->C_FindObjectsInit(session, template, 1);
     check_return_value(rv, "Find master key init");

     rv = p11->C_FindObjects(session, &object, 1, &objectCount);
     check_return_value(rv, "Find first master key");

     if (objectCount != 1) {
	     rv = (CKR_VENDOR_DEFINED | 1);
	     check_return_value(rv, "More than 1 master key found");
     }

     rv = p11->C_FindObjectsFinal(session);
     check_return_value(rv, "Find objects final");
     return object;
}


#define CKM_PLAINTEXT_HACK (CKM_VENDOR_DEFINED + 0x029A)

void
wrap_secret_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE secretKey, CK_OBJECT_HANDLE key)
{
     CK_RV rv;
     CK_UTF8CHAR label[80];
     CK_BYTE id[10];
     // CK_MECHANISM wrappingMech = {CKM_AES_KEY_WRAP, NULL, 0};
     // CK_MECHANISM wrappingMech = {CKM_PLAINTEXT_HACK, NULL, 0};
     CK_MECHANISM wrappingMech = {CKM_RSA_PKCS, NULL, 0};
     CK_BYTE_PTR pWrappedKey = NULL;
     CK_ULONG wrappedKeyLen = 0;
     char *file_name = NULL;
     size_t file_name_len = 1; // for \0

     memset(id, 0, 10);

     CK_ATTRIBUTE template[] = {
          {CKA_LABEL, label, sizeof(label)},
          {CKA_ID, id, sizeof(id)}
     };

     rv = p11->C_GetAttributeValue(session, secretKey, template, 2);
     check_return_value(rv, "get attribute value");

     file_name_len += template[0].ulValueLen;
     file_name_len += template[1].ulValueLen*2; // byte -> hex
     file_name = malloc(file_name_len);
     if (file_name == NULL) {
	     rv = CKR_HOST_MEMORY;
	     check_return_value(rv, "private key wrapping: file name buffer allocation");
     }
     memcpy(file_name, label, template[0].ulValueLen);
     for (int i = 0; i < template[1].ulValueLen; i++) {
	     sprintf(file_name + template[0].ulValueLen + i*2, "%02x", id[i]);
     }
     file_name[file_name_len - 1] = '\0';
     
     fprintf(stdout, "\tKey label-id: %s\n", file_name);



     p11->C_WrapKey(session, &wrappingMech, key, secretKey, NULL, &wrappedKeyLen);
     check_return_value(rv, "master key wrapping: get buffer length");
     pWrappedKey = malloc(wrappedKeyLen);
     if (pWrappedKey == NULL) {
	     rv = CKR_HOST_MEMORY;
	     check_return_value(rv, "private key wrapping: buffer allocation");
     }
     rv = p11->C_WrapKey(session, &wrappingMech, key, secretKey, pWrappedKey, &wrappedKeyLen);
     check_return_value(rv, "master key wrapping: real wrapping");
     FILE * fp = fopen(file_name, "w");
     fwrite(pWrappedKey, wrappedKeyLen, 1, fp);
     fclose(fp);
}

void
wrap_secret_keys(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
     CK_ATTRIBUTE template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) }
     };
     CK_ULONG objectCount;
     CK_OBJECT_HANDLE object;
     CK_OBJECT_HANDLE secretKey = NULL;

     secretKey = find_master_key(p11, session);

     rv = p11->C_FindObjectsInit(session, template, 1);
     check_return_value(rv, "Find objects init");

     rv = p11->C_FindObjects(session, &object, 1, &objectCount);
     check_return_value(rv, "Find first object");

     while (objectCount > 0) {
          wrap_secret_key(p11, session, secretKey, object);

          rv = p11->C_FindObjects(session, &object, 1, &objectCount);
          check_return_value(rv, "Find other objects");
     }

     rv = p11->C_FindObjectsFinal(session);
     check_return_value(rv, "Find objects final");
}

void
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
}

void
create_replica_key_pair(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_HANDLE publicKey, privateKey;
     CK_MECHANISM mechanism = {
          CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
     };
     CK_ULONG modulusBits = 2048;
     CK_BYTE publicExponent[] = { 1, 0, 1 };
     CK_BYTE subject[] = "replica1-keypair";
     CK_BYTE id[] = {0xa1};
     CK_ATTRIBUTE publicKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_WRAP, &true, sizeof(true)},
          {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
          {CKA_PUBLIC_EXPONENT, publicExponent, 3},
     };
     CK_ATTRIBUTE privateKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_PRIVATE, &true, sizeof(true)},
          {CKA_SENSITIVE, &false, sizeof(false)}, // prevents wrapping
          {CKA_UNWRAP, &true, sizeof(true)},
          {CKA_EXTRACTABLE, &true, sizeof(true)},
          {CKA_WRAP_WITH_TRUSTED, &false, sizeof(false)} // prevents wrapping
     };

     rv = p11->C_GenerateKeyPair(session,
                            &mechanism,
                            publicKeyTemplate,
			    sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            privateKeyTemplate,
			    sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            &publicKey,
                            &privateKey);
     check_return_value(rv, "generate key pair");
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
     create_master_key(p11, session);
     create_replica_key_pair(p11, session);
     wrap_secret_keys(p11, session);
     logout(p11, session);
     end_session(p11, session);
     finalize(p11);
     return EXIT_SUCCESS;
}

