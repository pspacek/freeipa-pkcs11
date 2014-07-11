/*
 * Copyright (C) 2014  Red Hat
 * Author: Martin Basti <mbasti@redhat.com>
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
#include "common.c"

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

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

char *asn1_publickey_str = "\
asn1=SEQUENCE:pubkeyinfo\n\
\n\
[pubkeyinfo]\n\
algorithm=SEQUENCE:rsa_alg\n\
pubkey=BITWRAP,SEQUENCE:rsapubkey\n\
\n\
[rsa_alg]\n\
algorithm=OID:rsaEncryption\n\
parameter=NULL\n\
\n\
[rsapubkey]\n\
n=INTEGER:0x%s\n\
\n\
e=INTEGER:0x%s\n\
";

    char *modulus_str = NULL;
    char *exponent_str = NULL;
    char *asn1_str = NULL;
    char *modulus_str_iter;
    char *exponent_str_iter;
    int asn1_strlen;

    ASN1_TYPE *asn1_type = NULL;

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
        modulus_str = (char *) malloc(1 + obj_template[2].ulValueLen * sizeof(CK_BYTE) * 2); //hexastring
        modulus_str[obj_template[2].ulValueLen * sizeof(CK_BYTE) * 2] = '\0';
        obj_template[2].pValue = modulus;
        exponent = (CK_BYTE_PTR) malloc(obj_template[3].ulValueLen * sizeof(CK_BYTE));
        exponent_str = (char *) malloc(1 + obj_template[3].ulValueLen * sizeof(CK_BYTE) * 2); //hexastring
        exponent_str[obj_template[3].ulValueLen * sizeof(CK_BYTE) * 2] = '\0'; 
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
             modulus_str_iter = modulus_str;
             for(i=0; obj_template[2].ulValueLen>i; ++i) {
            	 fprintf(stdout, "%02x", modulus[i]);
            	 modulus_str_iter += sprintf(modulus_str_iter, "%02x", modulus[i]);
             }
             fprintf(stdout, "\n");
        } else {
             fprintf(stderr, "\tmodulus too large, or not found\n");
        }
        if (obj_template[3].ulValueLen > 0) {
             fprintf(stdout, "\texponent: ");
             exponent_str_iter = exponent_str;
             for(i=0; obj_template[3].ulValueLen>i; ++i) {
            	 fprintf(stdout, "%02x", exponent[i]);
            	 exponent_str_iter += sprintf(exponent_str_iter, "%02x", exponent[i]);
             }
             fprintf(stdout, "\n");
        } else {
             fprintf(stderr, "\texponent too large, or not found\n");
        }
        asn1_strlen = strlen(exponent_str) + strlen(modulus_str) + strlen(asn1_publickey_str);
        asn1_str = (char *) malloc(asn1_strlen + 1);
        asn1_str[asn1_strlen] = '\0';
        sprintf(asn1_str, asn1_publickey_str, modulus_str, exponent_str);
        fprintf(stdout, "asn1: %s\n", asn1_str);
        
        asn1_type = ASN1_generate_nconf("IA5STRING:Hello World", NULL);
        //asn1_type = ASN1_generate_v3(asn1_str, NULL);
        
        if (asn1_type == NULL){
        	fprintf(stderr, "Invalid ASN1 string\n");
        } else {
        	
        }
        
        int r;
        unsigned char *pp = NULL;
        FILE *f;
        EVP_PKEY *pkey;
        BIGNUM *e;
        BIGNUM *n;
        RSA *rsa;
        rsa = RSA_new();
        pkey = EVP_PKEY_new();
        n = BN_bin2bn((const unsigned char *) modulus, obj_template[2].ulValueLen * sizeof(CK_BYTE), NULL);
        if( n==NULL ) {
        	fprintf(stderr, "Unable to convert modulus to BIGNUM");
        	exit(EXIT_FAILURE);
        }

        e = BN_bin2bn((const unsigned char *) exponent, obj_template[3].ulValueLen * sizeof(CK_BYTE), NULL);
        if( e==NULL ) {
        	fprintf(stderr, "Unable to convert exponent to BIGNUM");
        	exit(EXIT_FAILURE);
        }
        fprintf(stderr, "BIGNUM n:");
        BN_print_fp(stderr, n);
        fprintf(stderr, "\nBIGNUM e:");
        BN_print_fp(stderr, e);
        fprintf(stderr, "\n");
        rsa->n = n;
        rsa->e = e;
        //RSA_set_method(rsa, RSA_PKCS1_SSLeay());
        if (EVP_PKEY_set1_RSA(pkey,rsa)>0){
        	fprintf(stderr, "EVP_PKEY_set1_RSA success\n");
        }
        r = i2d_PUBKEY(pkey,&pp);

        f = fopen("pubkey.out", "w");
        fwrite(pp, r, 1, f);
        fclose(f);


        //BN_free(e);
        //BN_free(n);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        rv = p11->C_FindObjects(session, &object, 1, &objectCount);
        check_return_value(rv, "Find first object");
        //TODO free
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
