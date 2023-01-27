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
	printf("%s err out\n", __func__);
	cert = NULL;
	return cert;
}

int seal_pkcs7_envelope(X509 *cert, char *fin, char *fout, void *msg)
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
		goto seal_pkcs7_envelope_err;

	f_len = i2d_PKCS7(p7, &p_der);
	fp = fopen(fout, "wb");
	if (fp)
		fwrite(p_der, 1, f_len, fp);

	fclose(fp);
	PKCS7_free(p7);
	BIO_free(b_in);
	sk_X509_free(certs);

	return ret;

seal_pkcs7_envelope_err:
	//your error handle
	return ret;
}


EVP_PKEY *parse_prikey(char *pkey_file)
{
	FILE *fp = NULL;
	EVP_PKEY *pkey = NULL;

	//TODO d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);

	fp = fopen(pkey_file, "r");
	if (!fp)
		goto parse_prikey_err;

	if (!PEM_read_PrivateKey(fp, &pkey, NULL, NULL))
		goto parse_prikey_err;

	//TODO RSA private only

	return pkey;

parse_prikey_err:
	//your error handle
	printf("%s err out\n", __func__);
	if (fp)
		fclose(fp);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	return pkey;
}

/**
 * most situation private key already loaded to EVP_PKEY in buf
 *
 * Although the recipients certificate is not needed to decrypt
 * the data it is needed to locate the appropriate (of possible several)
 * recipients in the PKCS#7 structure.
 *
 */
int open_pkcs7_envelope(EVP_PKEY *prikey, X509 *cert, char *fin, char *fout)
{
	int len, ret = 0;
	unsigned char *p = NULL;
	FILE *fp = NULL;
	PKCS7 *p7 = NULL;
	BIO *b_out = NULL;

	fp = fopen(fin, "r");
	if (!fp)
		goto open_pkcs7_envelope_err;
	p7 = d2i_PKCS7_fp(fp, &p7);
	if (!p7)
		goto open_pkcs7_envelope_err;
	b_out = BIO_new(BIO_s_mem());
	if (!b_out)
		goto open_pkcs7_envelope_err;
	//now open the envelope
	if (1 != PKCS7_decrypt(p7, prikey, cert, b_out, PKCS7_BINARY))
		goto open_pkcs7_envelope_err;

	len = BIO_get_mem_data(b_out, &p);
	printf("%d\n", len);
	BIO_dump_fp(stdout, p, len); //debug

	//TODO write to fout file

	//free
	fclose(fp);
	PKCS7_free(p7);
	BIO_free(b_out);

	return ret;

open_pkcs7_envelope_err:
	//your error handle
	printf("%s err out\n", __func__);
	return ret;
}

//pkcs7_envelope [cert file] [private key file] [p7.der] [plain text]
int main(int argc, char * argv[])
{
	int ret = 0;

	//seal
	X509 *c = parse_cert(argv[1]);
	// if (c)
	// 	seal_pkcs7_envelope(c, NULL, argv[3], NULL);
	
	//open
	EVP_PKEY *pkey = parse_prikey(argv[2]);
	if (pkey)
		open_pkcs7_envelope(pkey, c, argv[3], argv[4]);

	return ret;
}