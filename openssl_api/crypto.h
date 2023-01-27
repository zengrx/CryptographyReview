#define SUCCESS 		0
#define MEM_ALLOC_FAIL	-1
#define VERIFY_FAIL		-2
#define FILE_OPEN_FAIL 	-3
#define KEY_LOAD_FAIL 	-4
#define EVP_ERROR		-5
#define SIGN_ERROR		-6
#define FILE_WRITE_FAIL	-7
#define VERIFY_ERROR	-8
#define CRYPTO_ERROR	-9
#define KEY_ERROR		-10
#define DATA_ERROR		-11
#define DIGEST_ERROR	-12
#define ENVELOPE_ERROR	-13
#define UNKNOWN_ERR		-255

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
					 unsigned char *cipher, int key_num);