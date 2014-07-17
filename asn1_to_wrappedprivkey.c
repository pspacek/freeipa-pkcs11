#include <stdio.h>
#include <stdlib.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

/**
 * Convert wrapped private key into PKCS8 privkeyinfo structure as DER format
 * reads Privatekey blob from stdin
 * Read from stdin, write to stdout
 */
int main(int argc, char *argv[]){

	ASN1_OBJECT *aobj = NULL;
	int parameter_type = V_ASN1_UNDEF;
	unsigned char *parameter_value = NULL;
	X509_SIG *p8 = NULL;
	FILE *fr;
	FILE *fw;
	int nid = 0;

	fr = fopen("privkeyinfo.out", "r");
	if (fr == NULL ) {
		fprintf(stderr, "Unable to open file\n");
		exit(EXIT_FAILURE);
	}

	p8 = d2i_PKCS8_fp(fr, NULL);
	if (p8 == NULL) {
		fprintf(stderr, "Conversion from ASN1 failed\n");
		exit(EXIT_FAILURE);
	}
	fclose(fr);
	// TODO for export to softhsm use p8 struct directly

	fw = fopen("wrappedprivkey.out", "w");
	if (fw == NULL){
		fprintf(stderr, "Unable to create output file\n");
		exit(EXIT_FAILURE);
	}

	fwrite(p8->digest->data, p8->digest->length, 1, fw);
	fclose(fw);


	//TODO use variables to insert values into softhsm
	aobj = ASN1_OBJECT_new();
	X509_ALGOR_get0(&aobj, &parameter_type, (void **) &parameter_value, p8->algor);

	nid = OBJ_obj2nid(aobj);
	fprintf(stdout, "Used algorithm: %s\n", OBJ_nid2sn(nid));


	X509_SIG_free(p8);
	//TODO free alg, os if needed

	return EXIT_SUCCESS;
}
