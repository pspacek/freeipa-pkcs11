#include <stdio.h>
#include <stdlib.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

/**
 * Convert wrapped private key into PKCS8 privkeyinfo structure as DER format
 * reads Privatekey blob from stdin
 * Read from stdin, write to stdout
 */
int main(int argc, char *argv[]){

	ASN1_OCTET_STRING* os = NULL;
	ASN1_OBJECT *aobj = NULL;
	X509_ALGOR *alg = NULL;
	X509_SIG *p8;
	FILE *fr;

	fr = fopen("wrapped.key", "r");
	int parameter_type = V_ASN1_UNDEF; // test 0
	unsigned char *parameter_value = NULL;

	unsigned char *pkeyblob = NULL;
	int l = 0;
	int size = 1024;
	int c;

	pkeyblob = (unsigned char *) malloc(size * sizeof(unsigned char));
	if (pkeyblob == NULL){
		fprintf(stderr, "pkeyblob malloc error\n");
		return EXIT_FAILURE;
	}

    while((c = getc(fr)) != EOF){
    	pkeyblob[l] = (unsigned char) c;
    	++l;
    	if(l>=size) {
    		size += 1024;
    		pkeyblob = (unsigned char *) realloc(pkeyblob, size * sizeof(unsigned char));
    		if (pkeyblob == NULL) {
    			fprintf(stderr, "Unable to realloc memory\n");
    			exit(EXIT_FAILURE);
    		}
    	}
    }
	fclose(fr);

	os = ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(os, pkeyblob, l)) {
		fprintf(stderr, "Unable to set OCTET_STRING\n");
		exit(EXIT_FAILURE);
	}

	//TODO set real used alg
	aobj = OBJ_nid2obj(NID_id_aes128_wrap); //ID of algorithm
	if (aobj == NULL){
		fprintf(stderr, "Unable to create algorithm object\n");
		exit(EXIT_FAILURE);
	}

	alg = X509_ALGOR_new();
	if (!X509_ALGOR_set0(alg, aobj, parameter_type, (void *) parameter_value)){
		fprintf(stderr, "Unable to set X509_ALGOR\n");
	} else if(alg == NULL){
		fprintf(stderr, "X509_ALGOR is null\n");
		exit(EXIT_FAILURE);
	}

	FILE *f;
	f = fopen("privkeyinfo.out", "w");
	if (f == NULL){
		fprintf(stderr, "Unable to create export file\n");
		exit(EXIT_FAILURE);
	}

	p8 = X509_SIG_new();
	p8->algor = alg; //algorithm
	p8->digest = os; //octet string -- wrapped key

	if (! i2d_PKCS8_fp(f, p8)) { //i2d_X509_SIG ? otestovat
		fprintf(stderr, "Conversion to ASN1 failed\n");
		exit(EXIT_FAILURE);
	}

	fclose(f);
	X509_SIG_free(p8);
	//TODO free alg, os if needed

	return EXIT_SUCCESS;
}
