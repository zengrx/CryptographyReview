#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

/**
 * parse a cert file, PEM or DER
 * @cert_file: cert file name
 * return X509 pointer obj
 * PKCS7 only support RSA algorithm for key_enc_algor,
 * so use X509_get_pubkey to check.
 */
X509 *parse_cert(char * cert_file /*, EVP_PKEY *pkey */)
{
	int ret = 0;
	FILE *fp = NULL;
	EVP_PKEY *pubkey = NULL;

	fp = fopen(cert_file, "rb");

	if (!fp)
		goto parse_cert_err;

	X509 *cert = X509_new();
	d2i_X509_fp(fp, &cert);
	if (!cert) //try PEM
	{
		rewind(fp);
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) //wrong file
			goto parse_cert_err;
	}
	pubkey = X509_get_pubkey(cert);
	if (!pubkey)
	{
		goto parse_cert_err;
	}

	int keylen = EVP_PKEY_size(pubkey);
	int pubkey_algo_id = EVP_PKEY_id(pubkey);

	switch(pubkey_algo_id) {
	case EVP_PKEY_RSA:
		printf("RSA key\n");
		break;

	default:
		printf("not support\n");
		break;
	}

	fclose(fp);

	return cert;

parse_cert_err:
	//your error handle
	printf("err out\n");
	cert = NULL;
	return cert;
}

int seal_pkcs7_envelop(X509 *cert, char *fin, char *fout, void *msg)
{
	int ret, f_len = 0;
	FILE *fp = NULL;
	unsigned char *p_der = NULL; //i2d pointer
	unsigned char *test_str = "this is a test message.";
	int str_len = strlen(test_str);
	STACK_OF(X509) *certs = sk_X509_new_null();
	PKCS7 *p7 = NULL;

	BIO *b_in = BIO_new_mem_buf(test_str, str_len);
	// BIO_dump_fp(stdout, test_str, str_len); //debug print

	sk_X509_push(certs, cert);
	//use aes 128 cbc as default, the iv at enc_data-algorithm-parameter
	p7 = PKCS7_encrypt(certs, b_in, EVP_aes_128_cbc(), PKCS7_BINARY);
	if (!p7)
		goto seal_pkcs7_envelop_err;

	f_len = i2d_PKCS7(p7, &p_der);
	fp = fopen(fout, "wb");
	if (fp)
		fwrite(p_der, 1, f_len, fp);

	fclose(fp);
	PKCS7_free(p7);
	BIO_free(b_in);
	sk_X509_free(certs);

	return ret;

seal_pkcs7_envelop_err:
	//your error handle
	return ret;
}

//pkcs7_envelope [cert file] [null] [p7.der] [null]
int main(int argc, char * argv[])
{
	int ret = 0;

	X509 *c = parse_cert(argv[1]);
	if (c)
		seal_pkcs7_envelop(c, argv[2], argv[3], NULL);

	return ret;
}