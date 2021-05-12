#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "crypto.h"

#ifdef LIB_MODE
#include <process.h>
#include <sys/slog2.h>
#define LOGI(...) slog2f(NULL, gettid(), SLOG2_INFO, __VA_ARGS__);
#else
#define LOGI(...) printf(__VA_ARGS__);
#endif

//------------------ENVELOPE FUNCTION START---------------------
//NB:
/* 
Initialise the envelope seal operation. This operation generates
a key for the provided cipher, and then encrypts that key a number
of times (one for each public key provided in the pub_key array). In
this example the array size is just one. This operation also
generates an IV and places it in iv.
	if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
		encrypted_key_len, iv, pub_key, 1))
		handleErrors();
*/
/**
 * Seal a envelope, use prng generate a key, iv value.
 * Encrypt symmetric "session" key, encrypt plain text.
 * @pubkey: public key file path
 * @plain: plain text data
 * @plain_len: plain text len
 * @encrypted_key: encrypted symmetric key data
 * @encrypted_key_len: encrypted_key len
 * @iv: IV data
 * @cipher: crypto result data
 * @key_num: pem number to generate encrytped_key
 * return cipher text length, < 0 error
 */
int envelope_seal(char *pub_key, unsigned char *plain, 
					 int plain_len, unsigned char **encrypted_key, 
					 int *encrypted_key_len, unsigned char *iv, 
					 unsigned char *cipher, int key_num)
{
	int ret = UNKNOWN_ERR;
	FILE *f_pkey = NULL;
	char pub_key_index[64];
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_PKEY **ppub_key = NULL; //public key obj

	ppub_key = (EVP_PKEY **)malloc(sizeof(EVP_PKEY *) * key_num);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		LOGI("EVP context create failed.\n");
		ret = EVP_ERROR;
		goto envelope_seal_err;
	}

	for (int i = 0; i < key_num; i++)
	{
		sprintf(pub_key_index, "%s%d.pem", pub_key, i);
		LOGI("Open %s\n", pub_key_index);
		f_pkey = fopen(pub_key_index, "r");
		if (!f_pkey)
		{
			LOGI("Open public key failed.\n");
			ret = FILE_OPEN_FAIL;
			goto envelope_seal_err;
		}

		if (!PEM_read_PUBKEY(f_pkey, &ppub_key[i], NULL, NULL))
		{
			LOGI("Loading public key failed.\n");
			ret = KEY_LOAD_FAIL;
			goto envelope_seal_err;
		}
		fclose(f_pkey);

		LOGI("key size is %d\n", EVP_PKEY_size(ppub_key[i]));

		//alloc memory for encrypted key
		*(encrypted_key + i) = (unsigned char *)malloc(sizeof(unsigned char) * EVP_PKEY_size(ppub_key[i]));
	}

	//init
	if(0 == EVP_SealInit(ctx, EVP_aes_128_cbc(), encrypted_key,
						 encrypted_key_len, iv, ppub_key, key_num))
	{
		LOGI("EVP seal init failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_seal_err;
	}

	//TODO EVP_SealUpdate EVP_SealFinal, EVP_SealUpate equl EVP_EncryptUpdate
	//TODO error handle

	return ret;

envelope_seal_err:
	LOGI("[OPENSSL_ERR] %s\n", ERR_error_string(ERR_get_error(), NULL));
	return ret;
}

/**
 * Open a envelope, get symmetric "session" key
 *
 *
 *
 *
 *
 *
 *
 */
int envelope_open(char *privkey, unsigned char *cipher, 
					 int chipher_len, unsigned char **enckey,
					 int enckey_len, unsigned char *iv,
					 unsigned char *plain)
{
	int ret = UNKNOWN_ERR;

	return ret;

envelope_open_err:
	return ret;
}

//------------------ENVELOPE FUNCTION END-----------------------

#ifndef LIB_MODE
int main(int argc, char *argv[])
{
	int ret = 0;
	int keynum = 2;
	unsigned char plain[] = "this is a test message.";
	//ek is a set of array, means maybe more then 1 key
	unsigned char **ek, iv[16];
	int *eklen = NULL;
	unsigned char cipher[1024];

	if (argc < 2)
	{
		LOGI("crypto_asymmetric [key number]\n");
		return 0;
	}

	// say if there're 2 keys
	// malloc size = pointerlen * keynum
	ek = (unsigned char **)malloc(sizeof(unsigned char *) * keynum);

	//TODO malloc eklen is sizeof(int * keynum)
	eklen = (int *)malloc(sizeof(int) * keynum);

	// OpenSSL_add_all_algorithms();
	unsigned char *ek1[2];
	envelope_seal("./keytest/rsapubkey", plain, sizeof(plain),
					 ek, eklen, iv, cipher, keynum);

	LOGI("=======RESULT HERE=======\n");
	LOGI("IV is:\n");
	for (int i = 0; i < 16; i++)
	{
		LOGI("%02x", iv[i]);
	}
	LOGI("\n");
	for (int i = 0; i < keynum; i++)
	{
		LOGI("encrypted key %d len is %d:\n", i, *(eklen + i));
		LOGI("%p\n", ek + i);
		for (int j = 0; j < *(eklen + i); j++)
		{
			LOGI("%02x", *(*(ek + i) + j));
			LOGI(" %p\n", (*(ek + i) + j));
			// LOGI("%02x", ek[i][j]);
		}
		LOGI("\n");
	}

	//free memory
	for (int i = 0; i < keynum; i++)
	{
		// free(*(ek1 + i));
		//A value, storage the address of pointer to an array
		//free this pointer to the array, a.k.a line pointer
		free(*(ek + i));
		LOGI("%p\n", (ek + i));
		*(ek + i) = NULL;
	}
	free(ek);
	ek = NULL;
	
	return ret;
}
#endif