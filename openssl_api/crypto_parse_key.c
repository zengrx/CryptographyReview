#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>


//TODO add x86_64 lib mode macro

#ifdef LIB_MODE
#include <process.h>
#include <sys/slog2.h>
#define LOGI(...) slog2f(NULL, gettid(), SLOG2_INFO, __VA_ARGS__)
#else
#define LOGI(...) printf(__VA_ARGS__)
#endif

void prettyPrint(char *tag, char *value, int len)
{
	LOGI("%s\n", tag);
	for (int i = 0; i < len; i += 2)
	{
		LOGI("%c%c ", value[i], value[i + 1]);
	}
	LOGI("\n");
}

int parsePublicKey(const char * key)
{
	int ret = 0;
	FILE *fin = NULL;
	EVP_PKEY *pkey = NULL;
	int keylen, pubkey_algo_id = 0;

	fin = fopen(key, "r");
	if (!fin)
		goto parse_pub_key_err;

	if (!PEM_read_PUBKEY(fin, &pkey, NULL, NULL))
	{
		LOGI("Loading public key failed.\n");
		goto parse_pub_key_err;
	}

	keylen = EVP_PKEY_size(pkey);

	pubkey_algo_id = EVP_PKEY_id(pkey);

	LOGI("%d, %d\n", keylen, pubkey_algo_id);

	switch(pubkey_algo_id) {
	case EVP_PKEY_RSA:
		LOGI("======>Parsing a %d RSA public key\n", keylen * 8);
		RSA *rsa_key = NULL;
		char *rsa_e_dec = NULL, *rsa_n_hex = NULL;
		BIGNUM *rsa_n = NULL, *rsa_e = NULL;
		rsa_key = EVP_PKEY_get0_RSA(pkey);
		RSA_get0_key(rsa_key, (const BIGNUM **)&rsa_n, (const BIGNUM **)&rsa_e, NULL);
		
		rsa_n_hex = BN_bn2hex(rsa_n);
		prettyPrint("Modulus:", rsa_n_hex, keylen * 2);

		rsa_e_dec = BN_bn2dec(rsa_e);
		int e_num = atoi(rsa_e_dec);
		LOGI("Exponent:\n");
		LOGI("%d (0x%x)\n", e_num, e_num);
		break;

	default:
		break;

	}

	EVP_PKEY_free(pkey);

	return ret;

parse_pub_key_err:
	LOGI("err\n");
	return ret;
}

/**
 * Parse private key
 *
 *
 */
int parsePrivKey(const char * key)
{
	int ret;
	FILE *fin = NULL;
	EVP_PKEY *pkey = NULL;
	int keylen, pubkey_algo_id = 0;

	fin = fopen(key, "r");
	if (!fin)
		goto parse_priv_key_err;

	if (!PEM_read_PrivateKey(fin, &pkey, NULL, NULL))
	{
		LOGI("Loading private key failed.\n");
		goto parse_priv_key_err;
	}

	keylen = EVP_PKEY_size(pkey);
	pubkey_algo_id = EVP_PKEY_id(pkey);

	switch (pubkey_algo_id) {
	case EVP_PKEY_RSA:
		LOGI("======>Parsing a %d RSA private key\n", keylen * 8);
		RSA *rsa_key = NULL;
		const BIGNUM **rsa_n, **rsa_e, **rsa_d, **rsa_p, **rsa_q;
		const BIGNUM *rsa_dp, *rsa_dq, *rsa_iq;
		char *rsa_e_dec = NULL, *rsa_n_hex = NULL, *rsa_d_hex = NULL;
		char *rsa_p_hex = NULL, *rsa_q_hex = NULL; //two primes
		char *rsa_dp_hex = NULL, *rsa_dq_hex = NULL, *rsa_iq_hex = NULL; //quick calc
		rsa_key = EVP_PKEY_get0_RSA(pkey);
		if (!rsa_key)
			goto parse_priv_key_err;

		//get key components
		RSA_get0_key(rsa_key, rsa_n, rsa_e, rsa_d); //phi(n) = phi(p) * phi(q)
		rsa_n_hex = BN_bn2hex(*rsa_n);
		rsa_e_dec = BN_bn2dec(*rsa_e);
		rsa_d_hex = BN_bn2hex(*rsa_d);

		prettyPrint("Modulus:", rsa_n_hex, keylen * 2);
		int e_num = atoi(rsa_e_dec);
		LOGI("Public Exponent:\n");
		LOGI("%d (0x%x)\n", e_num, e_num);
		keylen = strlen(rsa_d_hex);
		prettyPrint("Private Exponent:", rsa_d_hex, keylen);

		//get primes
		RSA_get0_factors(rsa_key, rsa_p, rsa_q);
		rsa_p_hex = BN_bn2hex(*rsa_p);
		rsa_q_hex = BN_bn2hex(*rsa_q);

		keylen = strlen(rsa_p_hex);
		prettyPrint("Prime1:", rsa_p_hex, keylen);
		keylen = strlen(rsa_q_hex);
		prettyPrint("Prime2:", rsa_q_hex, keylen);

		//get quick calculate components
		RSA_get0_crt_params(rsa_key, &rsa_dp, &rsa_dq, &rsa_iq);
		rsa_dp_hex = BN_bn2hex(rsa_dp);
		rsa_dq_hex = BN_bn2hex(rsa_dq);
		rsa_iq_hex = BN_bn2hex(rsa_iq);

		keylen = strlen(rsa_dp_hex);
		prettyPrint("Private exponent mod p:", rsa_dp_hex, keylen);
		keylen = strlen(rsa_dq_hex);
		prettyPrint("Private exponent mod q:", rsa_dq_hex, keylen);
		keylen = strlen(rsa_iq_hex);
		prettyPrint("inverse q mod p:", rsa_iq_hex, keylen);

		break;

	default:
		break;
	}

	EVP_PKEY_free(pkey);

	return ret;

parse_priv_key_err:
	LOGI("err\n");
	return ret;
}

int main(int argc, const char * argv[])
{
	int ret = 0;

	//TODO coding here
	parsePublicKey(argv[1]);
	parsePrivKey(argv[2]);


	return ret;
}