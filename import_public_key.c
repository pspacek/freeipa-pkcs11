#include "common.c"

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

//import from STDIN
CK_RV
import_public_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_BYTE_PTR modulus = NULL;
	int modulus_len = 0;
	CK_BYTE_PTR exponent = NULL;
	int exponent_len = 0;
	
    unsigned char *pp = NULL;
    EVP_PKEY *pkey;
    RSA *rsa;
    long l;
    long size;
    int c;
    
    l=0;
    size = 1024;
    pp = (unsigned char *) malloc(size * sizeof(unsigned char));
    
    /* load PUBKEY from STDIN */
    while((c = getchar()) != EOF){
    	pp[l] = (unsigned char) c;
    	++l;
    	if(l>=size) {
    		size += 1024;
    		pp = (unsigned char *) realloc(pp, size * sizeof(unsigned char));
    		if (pp == NULL) {
    			fprintf(stderr, "Unable to realloc memory");
    			exit(EXIT_FAILURE);
    		}
    	}
    }

    pkey = d2i_PUBKEY(NULL, (const unsigned char **) &pp, l);
    //TODO detect if type is RSA

    rsa = EVP_PKEY_get1_RSA(pkey);
    fprintf(stderr, "BIGNUM n:");
    BN_print_fp(stderr, rsa->n);
    fprintf(stderr, "\nBIGNUM e:");
    BN_print_fp(stderr, rsa->e);
    fprintf(stderr, "\n");
    
    //convert BIGNUM to binary array
    modulus = (CK_BYTE_PTR) malloc(BN_num_bytes(rsa->n));
    modulus_len = BN_bn2bin(rsa->n, (unsigned char *) modulus);
    exponent = (CK_BYTE_PTR) malloc(BN_num_bytes(rsa->e));
    exponent_len = BN_bn2bin(rsa->e, (unsigned char *) exponent);
    //TODO get Type of algorithm from PUBKEY
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_ULONG modulusBits = 2048;
    CK_BYTE subject[] = "imported-pubkey";
    CK_BYTE id[] = {6,6,6};
    CK_OBJECT_HANDLE data;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ATTRIBUTE publicKeyTemplate[] = {
    	//TODO parameters
    	//TODO type RSA.. etc
         {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
         {CKA_ID, id, sizeof(id)},
         {CKA_LABEL, subject, sizeof(subject) - 1},
         {CKA_TOKEN, &true, sizeof(true)},
         {CKA_WRAP, &true, sizeof(true)},
         //{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
         {CKA_PUBLIC_EXPONENT, exponent, exponent_len},
         {CKA_MODULUS, modulus, modulus_len},
         {CKA_CLASS, &keyClass, sizeof(keyClass)},
    };
    
    rv = p11->C_CreateObject(session, publicKeyTemplate, 8, &data);
    check_return_value(rv, "create public key object");
    
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    return CKR_OK;
}


CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return import_public_key(p11, session);
}
