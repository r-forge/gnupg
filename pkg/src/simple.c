/*
 * simple.c
 *
 *  Created on: May 2, 2011
 *      Author: mario
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <R.h>
#include <Rdefines.h>
#include <Rinternals.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "simple.h"

/*
 ** encodeblock
 **
 ** encode 3 8-bit binary bytes as 4 '6-bit' characters
 */
void encodeblock(const unsigned char in[3], unsigned char out[4], int len) {
	out[0] = cb64[in[0] >> 2];
	out[1] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
	out[2] = (unsigned char) (len > 1 ? cb64[((in[1] & 0x0f) << 2) | ((in[2]
			& 0xc0) >> 6)] : '=');
	out[3] = (unsigned char) (len > 2 ? cb64[in[2] & 0x3f] : '=');
}

/*
 ** decodeblock
 **
 ** decode 4 '6-bit' characters into 3 8-bit binary bytes
 */
void decodeblock(const unsigned char in[4], unsigned char out[3]) {
	out[0] = (unsigned char) (in[0] << 2 | in[1] >> 4);
	out[1] = (unsigned char) (in[1] << 4 | in[2] >> 2);
	out[2] = (unsigned char) (((in[2] << 6) & 0xc0) | in[3]);
}

void strencode(const unsigned char * in, unsigned char ** out) {
	size_t lenin = strlen((char*) in);
	int block_count = ceil((float) lenin / 3);
	*out = malloc(block_count * 4 + 1);
	(*out)[block_count * 4] = 0;

	int pos, len = 3, todolen = lenin;
	for (pos = 0; pos < block_count; pos++) {
		if (todolen < 3)
			len = todolen;
		encodeblock(in + pos * 3, *out + pos * 4, len);
		todolen -= 3;
	}
}

void strdecode(const unsigned char * in, unsigned char ** out) {
	size_t lenin = strlen((char*) in);
	int block_count = ceil((float) lenin / 4);
	*out = malloc(block_count * 3 + 1);
	(*out)[block_count * 3] = 0;

}

unsigned char *signSomeText(const char * key_file_name,
		unsigned char * string_to_sign) {

	size_t mdlen = strlen((char*) string_to_sign);

	FILE *rsa_pkey_file;

	if ((rsa_pkey_file = fopen(key_file_name, "r")) == NULL) {
		fprintf(stderr, "error opening Private Key file\n");
		return NULL;
	}

	EVP_PKEY *priv_key_evp = NULL;
	if (!PEM_read_PrivateKey(rsa_pkey_file, &priv_key_evp, NULL, NULL)) {
		fprintf(stderr, "Error reading Private Key file.\n");
		return NULL;
	}

	size_t siglen = RSA_size(priv_key_evp->pkey.rsa);
	unsigned char *sig = OPENSSL_malloc(siglen);
	if (!sig) {
		fprintf(stderr, "Error allocating signature buffer.\n");
		return NULL;
	}

	unsigned char * digest = SHA1(string_to_sign, mdlen, NULL);

	if (!RSA_sign_ASN1_OCTET_STRING(priv_key_evp->type, digest,
			SHA_DIGEST_LENGTH, sig, &siglen, priv_key_evp->pkey.rsa)) {
		fprintf(stderr, "Error signing text.\n");
		return NULL;
	}

	if (!RSA_verify_ASN1_OCTET_STRING(priv_key_evp->type, digest,
			SHA_DIGEST_LENGTH, sig, siglen, priv_key_evp->pkey.rsa)) {
		fprintf(stderr, "Error verifying text.\n");
		return NULL;
	}

	unsigned char * result = NULL;
	strencode(sig, &result);
	free(sig);
	return result;
}

int verifyTextSignature(const char * key_file_name,
		unsigned char * string_to_sign, char * sig64) {

	FILE *rsa_pkey_file;

	if ((rsa_pkey_file = fopen(key_file_name, "r")) == NULL) {
		fprintf(stderr, "error opening Private Key file\n");
		return NULL;
	}

	EVP_PKEY *priv_key_evp = NULL;
	if (!PEM_read_PrivateKey(rsa_pkey_file, &priv_key_evp, NULL, NULL)) {
		fprintf(stderr, "Error reading Private Key file.\n");
		return NULL;
	}

	size_t mdlen = strlen((char*) string_to_sign);
	unsigned char * sig = NULL;
	strdecode(sig64, &sig);
	size_t siglen = RSA_size(priv_key_evp->pkey.rsa);

	unsigned char * digest = SHA1(string_to_sign, mdlen, NULL);

	int result = RSA_verify_ASN1_OCTET_STRING(priv_key_evp->type, digest,
			SHA_DIGEST_LENGTH, sig, siglen, priv_key_evp->pkey.rsa);

	free(sig);
	return result;
}
/*
 * return a C string.  you are responsible for its deallocation (call free).
 */
unsigned char * strFromSEXP(SEXP theString) {
	size_t resultlen;
	char * orig;
	if (IS_RAW(theString)) { /* Txt is either RAW */
		resultlen = LENGTH(theString);
		orig = (char*) RAW(theString);
	} else { /* or a string */
		orig = (char*) STRING_VALUE(theString);
		resultlen = strlen(orig);
	}
	unsigned char * result = malloc(resultlen + 1);
	strncpy((char*) result, orig, resultlen);
	result[resultlen] = 0;
	return result;
}
