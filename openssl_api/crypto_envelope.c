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
	int len, cipher_len = 0;

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
	if (0 == EVP_SealInit(ctx, EVP_aes_128_cbc(), encrypted_key,
						 encrypted_key_len, iv, ppub_key, key_num))
	{
		LOGI("EVP seal init failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_seal_err;
	}

	//TODO EVP_SealUpdate EVP_SealFinal, EVP_SealUpate equl EVP_EncryptUpdate
	//TODO error handle
	//TODO use while() get real world input
	if (1 != EVP_SealUpdate(ctx, cipher, &len, plain, plain_len))
	{
		LOGI("EVP seal update data failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_seal_err;
	}
	cipher_len = len;

	if (1 != EVP_SealFinal(ctx, cipher + len, &len))
	{
		LOGI("EVP seal final failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_seal_err;
	}
	cipher_len += len;
	ret = cipher_len;

	return ret;

envelope_seal_err:
	LOGI("[OPENSSL_ERR] %s\n", ERR_error_string(ERR_get_error(), NULL));
	//TODO release memory
	return ret;
}

/**
 * Open a envelope, get symmetric "session" key
 * The difference between seal function is for the recv side,
 * just need symmetric key to decrypt message, so one pointer 
 * to encrypted key is enough. But the send side may needs 
 * double pointer for some muti-operation.
 * @privkey: private key file path
 * @cipher: encrypted data
 * @cipher_len: encrypted data len
 * @encrypted_key: encrypted symmertic key
 * @encrypted_key_len: encrypted symmertic key len
 * @iv: IV
 * @plain: decrypt result data
 * return plain text lenght, < 0 for error
 */
int envelope_open(char *privkey, unsigned char *cipher, 
				  int cipher_len, unsigned char *encrypted_key,
				  int encrypted_key_len, unsigned char *iv,
				  unsigned char *plain)
{
	int ret             = UNKNOWN_ERR;
	FILE *f_pkey        = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_PKEY *ppub_key  = NULL; //private key obj
	int len, plain_len = 0;
	int secret_key_len  = 0;

	f_pkey = fopen(privkey, "r");
	if (!f_pkey)
	{
		LOGI("Read private key failed.\n");
		ret = FILE_OPEN_FAIL;
		goto envelope_open_err;
	}

	if (!PEM_read_PrivateKey(f_pkey, &ppub_key, NULL, NULL))
	{
		LOGI("Loading private key failed.\n");
		ret = KEY_LOAD_FAIL;
		goto envelope_open_err;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		LOGI("EVP context create failed.\n");
		ret = EVP_ERROR;
		goto envelope_open_err;
	}

	secret_key_len = EVP_OpenInit(ctx, EVP_aes_128_cbc(), encrypted_key,
					 				   encrypted_key_len, iv, ppub_key);
	if (secret_key_len <= 0)
	{
		LOGI("EVP open init failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_open_err;
	}

	//TODO add a while() loop for long data
	if (1 != EVP_OpenUpdate(ctx, plain, &len, cipher, cipher_len))
	{
		LOGI("EVP open update data failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_open_err;
	}
	plain_len = len;

	if (1 != EVP_OpenFinal(ctx, plain + len, &len))
	{
		LOGI("EVP open final failed.\n");
		ret = ENVELOPE_ERROR;
		goto envelope_open_err;
	}
	plain_len += len;

	return plain_len;

envelope_open_err:
	//TODO free memory
	return ret;
}

//------------------ENVELOPE FUNCTION END-----------------------

#ifndef LIB_MODE
int main(int argc, char *argv[])
{
	int ret = 0;
	int keynum = 2;
	unsigned char plain[] = "this is a test message3eeeeeeeeeeeeeeeeee.";
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
	ret = envelope_seal("./keytest/rsapubkey", plain, sizeof(plain),
					 ek, eklen, iv, cipher, keynum);

	LOGI("=======SEAL RESULT HERE=======\n");
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
			// LOGI(" %p\n", (*(ek + i) + j));
			// LOGI("%02x", ek[i][j]);
		}
		LOGI("\n");
	}

	LOGI("cipher len is %d\n", ret);
	for (int i = 0; i < ret; i++)
	{
		LOGI("%02x", cipher[i])
	}
	LOGI("\n");

	LOGI("=======OPEN RESULT HERE=======\n");
	unsigned char outbuf[128];
	ret = envelope_open("./keytest/rsaprikey1.pem", cipher, ret, 
						*(ek + 1), *(eklen + 1), iv, outbuf);
	LOGI("encrypted secret key is:\n");
	for (int i = 0; i < *(eklen + 1); i++)
	{
		LOGI("%02x", *(*(ek + 1) + i));
	}
	LOGI("\n");

	LOGI("plain len is %d\nplain text:\n", ret);
	for (int i = 0; i < ret; i++)
	{
		LOGI("%c", outbuf[i]);
	}
	LOGI("\n");

	LOGI("=======FREE MEMORY=======\n");
	//free memory
	for (int i = 0; i < keynum; i++)
	{
		// free(*(ek1 + i));
		//A value, storage the address of pointer to an array
		//free this pointer to the array, a.k.a line pointer
		free(*(ek + i));
		// LOGI("%p\n", (ek + i));
		*(ek + i) = NULL;
	}
	free(ek);
	ek = NULL;
	
	return ret;
}
#endif