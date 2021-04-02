#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "AES.h"

//function to sbox
uint8_t aes_sub_sbox(uint8_t val)
{
    return g_aes_sbox[val];
}

//function to inv-sbox
uint8_t inv_sub_sbox(uint8_t val)
{
    return g_inv_sbox[val];
}

//function used in the Key Expansion routine that takes a four-byte input word
//and applies an sbox to each of the four bytes to produce an output word.
//32bits double word which is the four-byte input
uint32_t aes_sub_dword(uint32_t val)
{
    uint32_t tmp = 0;

    tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 0) & 0xFF))) << 0;
    tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 8) & 0xFF))) << 8;
    tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 16) & 0xFF))) << 16;
    tmp |= ((uint32_t)aes_sub_sbox((uint8_t)((val >> 24) & 0xFF))) << 24;

    return tmp;
}

//function used in the Key Expansion routine that takes a four-byte word and
//performs a cyclic permutation
//32bits double word as input
uint32_t aes_rot_dword(uint32_t val)
{
    uint32_t tmp = val;

    return (val >> 8) | ((tmp & 0xFF) << 24);
}

//function to swap byte value in a double word input
uint32_t aes_swap_dword(uint32_t val)
{
    return (((val & 0x000000FF) << 24) |
            ((val & 0x0000FF00) << 8) |
            ((val & 0x00FF0000) >> 8) |
            ((val & 0xFF000000) >> 24));
}

//basc xtime, multiplication X in GF(2^8)
uint8_t GF256_xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

//AES xtime rounds
uint8_t aes_xtimes(uint8_t x, int ts)
{
    while (ts-- > 0)
    {
        x = GF256_xtime(x);
    }

    return x;
}

//the polynomials multiplication in GF(2^8)
//basically let polynomial X do xtimes calculation, get all intermediate results
//then xor those intermediate result with all 1 coefficient of polynomial Y
uint8_t aes_mul(uint8_t x, uint8_t y)
{
    /*
     * encrypt: y has only 2 bits: can be 1, 2 or 3
     * decrypt: y could be any value of 9, b, d, or e
     */

    return ((((y >> 0) & 0x01) * aes_xtimes(x, 0)) ^
            (((y >> 1) & 0x01) * aes_xtimes(x, 1)) ^
            (((y >> 2) & 0x01) * aes_xtimes(x, 2)) ^
            (((y >> 3) & 0x01) * aes_xtimes(x, 3)) ^
            (((y >> 4) & 0x01) * aes_xtimes(x, 4)) ^
            (((y >> 5) & 0x01) * aes_xtimes(x, 5)) ^
            (((y >> 6) & 0x01) * aes_xtimes(x, 6)) ^
            (((y >> 7) & 0x01) * aes_xtimes(x, 7)));
}

//aes hex dump
void aes_dump(char *msg, uint8_t *data, int len)
{
    return;
    int i, j;

    printf("   %s: ", msg);
    for (i = 0; i < len / 4; i++)
    {
        printf("\r\n");
        for (j = 0; j < 4; j++)
        {
            if (j == 0)
            {
                printf("%10.2x", data[j * 4 + i]);
            }
            else
            {
                printf(" %02x", data[j * 4 + i]);
            }
        }
    }
    printf("\n");
}

/*
 * section 5.1, aka. PART A: encryption process
 */

//5.1.1 sub-bytes
//use s-box to convert raw data
void aes_sub_bytes(AES_CYPHER_T mode, uint8_t *state)
{
    int i, j;

    for (i = 0; i < g_aes_nb[mode]; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i * 4 + j] = aes_sub_sbox(state[i * 4 + j]);
        }
    }
}

//5.1.2 shift rows
//cyclically shifted over the given number
void aes_shift_rows(AES_CYPHER_T mode, uint8_t *state)
{
    // uint8_t *s = (uint8_t *)state;
    int i, j, r;

    for (i = 1; i < g_aes_nb[mode]; i++)
    {
        for (j = 0; j < i; j++)
        {
            uint8_t tmp = state[i];
            for (r = 0; r < g_aes_nb[mode]; r++)
            {
                state[i + r * 4] = state[i + (r + 1) * 4];
            }
            state[i + (g_aes_nb[mode] - 1) * 4] = tmp;
        }
    }
}

//5.1.3 mix columns
//each column considered as a polynomials multiplied with
//a fixed polynomial a(x) then modulo x^4+1 over GF(2^8)
//note the given a(x) = {03}x^3 + {01}x^2 + {01}x^1 + {02}x^0
void aes_mix_columns(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t y[16] = {2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2};
    uint8_t s[4];
    //i-column index of state, max is 4
    //j-multiply index, max is 4
    //r-row index of a(x) replaced martix, max is 4
    int i, j, r;

    //state multiplicate fixed a(x)
    for (i = 0; i < g_aes_nb[mode]; i++)
    {
        //each column of state and a(x)
        for (r = 0; r < 4; r++)
        {
            s[r] = 0;
            //column multiply a(x)
            for (j = 0; j < 4; j++)
            {
                s[r] = s[r] ^ aes_mul(state[i * 4 + j], y[r * 4 + j]);
                // printf("%02x ", s[r]);
            }
        }
        // printf("\r\n");
        //get new column
        for (r = 0; r < 4; r++)
        {
            state[i * 4 + r] = s[r];
        }
    }
}

//5.1.4 add round key
void aes_add_round_key(AES_CYPHER_T mode, uint8_t *state, uint8_t *round, int nr)
{
    uint32_t *w = (uint32_t *)round;
    uint32_t *s = (uint32_t *)state;
    int i;

    for (i = 0; i < g_aes_nb[mode]; i++)
    {
        s[i] ^= w[nr * g_aes_nb[mode] + i];
    }
}

/*
 * section 5.2, aka. PART B: key schedule
 */

/* 
 * nr: number of rounds
 * nb: number of columns comprising the state, nb = 4 dwords (16 bytes)
 * nk: number of 32-bit words comprising cipher key, nk = 4, 6, 8 (KeyLength/(4*8))
 */

//key expansion, get round key
void aes_key_expansion(AES_CYPHER_T mode, uint8_t *key, uint8_t *round)
{
    uint32_t *w = (uint32_t *)round;
    uint32_t t;
    int i = 0;

    printf("Key Expansion:\n");
    do
    {
        w[i] = *((uint32_t *)&key[i * 4 + 0]);
        // printf("    %2.2d:  rst: %8.8x\n", i, aes_swap_dword(w[i]));
    } while (++i < g_aes_nk[mode]);

    do
    {
        // printf("    %2.2d: ", i);
        if ((i % g_aes_nk[mode]) == 0)
        {
            t = aes_rot_dword(w[i - 1]);
            // printf(" rot: %8.8x", aes_swap_dword(t));
            t = aes_sub_dword(t);
            // printf(" sub: %8.8x", aes_swap_dword(t));
            // printf(" rcon: %8.8x", g_aes_rcon[i / g_aes_nk[mode] - 1]);
            t = t ^ aes_swap_dword(g_aes_rcon[i / g_aes_nk[mode] - 1]);
            // printf(" xor: %8.8x", t);
        }
        else if (g_aes_nk[mode] > 6 && (i % g_aes_nk[mode]) == 4)
        {
            t = aes_sub_dword(w[i - 1]);
            // printf(" sub: %8.8x", aes_swap_dword(t));
        }
        else
        {
            t = w[i - 1];
            // printf(" equ: %8.8x", aes_swap_dword(t));
        }
        w[i] = w[i - g_aes_nk[mode]] ^ t;
        // printf(" rst: %8.8x\n", aes_swap_dword(w[i]));
    } while (++i < g_aes_nb[mode] * (g_aes_rounds[mode] + 1));

    /* key can be discarded (or zeroed) from memory */
}

/**
 * section 5.3 Inverse Cipher 
 */

//5.3.1 InvShiftRows
//same shift direction with shiftrows, different times
void inv_shift_rows(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t *s = (uint8_t *)state;
    int i, j, r;

    for (i = 1; i < g_aes_nb[mode]; i++)
    {
        for (j = 0; j < g_aes_nb[mode] - i; j++)
        {
            uint8_t tmp = s[i];
            for (r = 0; r < g_aes_nb[mode]; r++)
            {
                s[i + r * 4] = s[i + (r + 1) * 4];
            }
            s[i + (g_aes_nb[mode] - 1) * 4] = tmp;
        }
    }
}

//5.3.2 InvSubBytes
//use inverse s-box to convert input data
void inv_sub_bytes(AES_CYPHER_T mode, uint8_t *state)
{
    int i, j;

    for (i = 0; i < g_aes_nb[mode]; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i * 4 + j] = inv_sub_sbox(state[i * 4 + j]);
        }
    }
}

//5.3.3 InvMixColumns
//polynomial a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x^1 + {0e}x^0
void inv_mix_columns(AES_CYPHER_T mode, uint8_t *state)
{
    uint8_t y[16] = {0x0e, 0x0b, 0x0d, 0x09,
                     0x09, 0x0e, 0x0b, 0x0d,
                     0x0d, 0x09, 0x0e, 0x0b,
                     0x0b, 0x0d, 0x09, 0x0e};
    uint8_t s[4];
    int i, j, r;

    for (i = 0; i < g_aes_nb[mode]; i++)
    {
        for (r = 0; r < 4; r++)
        {
            s[r] = 0;
            for (j = 0; j < 4; j++)
            {
                s[r] = s[r] ^ aes_mul(state[i * 4 + j], y[r * 4 + j]);
            }
        }
        for (r = 0; r < 4; r++)
        {
            state[i * 4 + r] = s[r];
        }
    }
}

//test equ extension
//key expansion, get round key
/**
 * 5.3.5 Equivalent Inverse Cipher
 * Fig.15 For the Equivalent function, key expansion should add some codes.
 * new para@inv: crypto flag, type-uint8_t, 0-encrypt 1-decrypt
 */
void equ_key_expansion(AES_CYPHER_T mode, uint8_t *key, uint8_t *round, uint8_t inv)
{
    uint32_t *w = (uint32_t *)round;
    uint32_t t;
    int i = 0;

    printf("Key Expansion:\n");
    do
    {
        w[i] = *((uint32_t *)&key[i * 4 + 0]);
        // printf("    %2.2d:  rst: %8.8x\n", i, aes_swap_dword(w[i]));
    } while (++i < g_aes_nk[mode]);

    do
    {
        // printf("    %2.2d: ", i);
        if ((i % g_aes_nk[mode]) == 0)
        {
            t = aes_rot_dword(w[i - 1]);
            // printf(" rot: %8.8x", aes_swap_dword(t));
            t = aes_sub_dword(t);
            // printf(" sub: %8.8x", aes_swap_dword(t));
            // printf(" rcon: %8.8x", g_aes_rcon[i / g_aes_nk[mode] - 1]);
            t = t ^ aes_swap_dword(g_aes_rcon[i / g_aes_nk[mode] - 1]);
            // printf(" xor: %8.8x", t);
        }
        else if (g_aes_nk[mode] > 6 && (i % g_aes_nk[mode]) == 4)
        {
            t = aes_sub_dword(w[i - 1]);
            // printf(" sub: %8.8x", aes_swap_dword(t));
        }
        else
        {
            t = w[i - 1];
            // printf(" equ: %8.8x", aes_swap_dword(t));
        }
        w[i] = w[i - g_aes_nk[mode]] ^ t;
        // printf(" rst: %8.8x\n", aes_swap_dword(w[i]));
    } while (++i < g_aes_nb[mode] * (g_aes_rounds[mode] + 1));

    //Fig.15 implement equivalent inverse cipher
    if (1 == inv)
    {
        //note change of type
        //invMixColumns operates 2d array, round key is words array
        uint8_t *inv_k = (uint8_t *)w;
        uint8_t tmp_roundkey[4 * 4 * 15] = {0};
        for (i = 1; i < g_aes_rounds[mode]; i++)
        {
            memcpy(&tmp_roundkey[(i - 1) * 16], &inv_k[i * 16], 16);
            // aes_dump("[tmpkey]", &tmp_roundkey[(i - 1) * 16], 16);
            // printf("\r\n%d", i);
            inv_mix_columns(mode, &tmp_roundkey[(i - 1) * 16]);
            // aes_dump("[tmpkey]", &tmp_roundkey[(i - 1) * 16], 16);
            // printf("=============\r\n");
        }

        //copy new round key, from round 1 to round (n-1)
        memcpy(w + 4, tmp_roundkey, 4 * 4 * (g_aes_rounds[mode] - 1));
    }

    /* key can be discarded (or zeroed) from memory */
}

//AES encryption
/**
 * section 5.1 Cipher
 * figure 5
 */
int aes_encrypt(AES_CYPHER_T mode, uint8_t *data, uint8_t *key)
{
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0};      /* state */

    int nr;

    /* key expansion */
    aes_key_expansion(mode, key, w);

    /* init state from user buffer (plaintext) */
    memcpy(s, data, 4 * g_aes_nb[mode]);

    /* start AES cypher loop over all AES rounds */
    for (nr = 0; nr <= g_aes_rounds[mode]; nr++)
    {
        printf(" [Round %d]\n", nr);
        aes_dump("input", s, 4 * g_aes_nb[mode]);

        if (nr > 0)
        {
            /* do SubBytes */
            aes_sub_bytes(mode, s);
            aes_dump("SubBytes", s, 4 * g_aes_nb[mode]);

            /* do ShiftRows */
            aes_shift_rows(mode, s);
            aes_dump("ShiftRows", s, 4 * g_aes_nb[mode]);

            if (nr < g_aes_rounds[mode])
            {
                /* do MixColumns */
                aes_mix_columns(mode, s);
                aes_dump("MixColumns", s, 4 * g_aes_nb[mode]);
            }
        }

        /* do AddRoundKey */
        aes_add_round_key(mode, s, w, nr);
        aes_dump("RoundKey", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);
        aes_dump("state", s, 4 * g_aes_nb[mode]);
    }

    /* save state (cypher) to user buffer */
    memcpy(data, s, 4 * g_aes_nb[mode]);

    printf("Output:\n");
    aes_dump("cypher", data, 4 * g_aes_nb[mode]);

    return 0;
}

//AES decryption
//section Fig.12
int aes_decrypt(AES_CYPHER_T mode, uint8_t *data, uint8_t *key)
{
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0};      /* state */

    int nr;

    /* key expansion */
    aes_key_expansion(mode, key, w);

    memcpy(s, data, 4 * g_aes_nb[mode]);

    for (nr = g_aes_rounds[mode]; nr >= 0; nr--)
    {
        printf(" [Round %d]\n", g_aes_rounds[mode] - nr);
        aes_dump("input", s, 4 * g_aes_nb[mode]);

        if (nr < g_aes_rounds[mode])
        {
            inv_shift_rows(mode, s);
            aes_dump("invShiftRows", s, 4 * g_aes_nb[mode]);

            inv_sub_bytes(mode, s);
            aes_dump("invSubBytes", s, 4 * g_aes_nb[mode]);
        }

        aes_add_round_key(mode, s, w, nr);
        aes_dump("RoundKey", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);
        aes_dump("state", s, 4 * g_aes_nb[mode]);

        if (nr < g_aes_rounds[mode] && nr > 0)
        {
            inv_mix_columns(mode, s);
            aes_dump("invMixColumns", s, 4 * g_aes_nb[mode]);
        }
    }

    /* save state (cypher) to user buffer */
    memcpy(data, s, 4 * g_aes_nb[mode]);
    printf("Output:\n");
    aes_dump("plain", data, 4 * g_aes_nb[mode]);

    return 0;
}

//AES decryption 2
/**
 * section 5.3.5
 * Equivalent Inverse Cipher
 * switch functions call order to get a efficient struct
 */
int aes_equ_decrypt(AES_CYPHER_T mode, uint8_t *data, uint8_t *key)
{
    uint8_t w[4 * 4 * 15] = {0}; /* round key */
    uint8_t s[4 * 4] = {0};      /* state */

    int nr;

    /* key expansion for equ-inverse algorithm*/
    equ_key_expansion(mode, key, w, 1);

    memcpy(s, data, 4 * g_aes_nb[mode]);

    /* start AES cypher loop over all AES rounds */
    for (nr = g_aes_rounds[mode]; nr >= 0; nr--)
    {
        printf(" [Round %d]\n", g_aes_rounds[mode] - nr);
        aes_dump("input", s, 4 * g_aes_nb[mode]);

        if (nr < g_aes_rounds[mode])
        {
            inv_sub_bytes(mode, s);
            aes_dump("invSubBytes", s, 4 * g_aes_nb[mode]);

            inv_shift_rows(mode, s);
            aes_dump("invShiftRows", s, 4 * g_aes_nb[mode]);

            if (nr > 0)
            {
                inv_mix_columns(mode, s);
                aes_dump("invMixColumns", s, 4 * g_aes_nb[mode]);
            }
        }

        /* do AddRoundKey */
        aes_add_round_key(mode, s, w, nr);
        aes_dump("RoundKey", &w[nr * 4 * g_aes_nb[mode]], 4 * g_aes_nb[mode]);
        aes_dump("state", s, 4 * g_aes_nb[mode]);
    }

    /* save state (cypher) to user buffer */
    memcpy(data, s, 4 * g_aes_nb[mode]);

    printf("Output:\n");
    aes_dump("plain", data, 4 * g_aes_nb[mode]);

    return 0;
}

//------------------------------
//-----------PADDING------------
//------------------------------

/**
 * Byte Padding, ISO/IEC 7816-4
 * Since the basic data unit is byte, so set 0x80
 * Add another 16 bytes when len equ multiple of 16,
 */
int BytePadding(uint8_t **data, int *len)
{
    int ret, len_tmp, n;
    uint8_t * datap;
    len_tmp = *len;

    n = 16 - (len_tmp % 16);
    len_tmp += n;
    datap = realloc(*data, len_tmp);
    if (!datap)
    {
        //realloc failed.
        return -1;
    }
    *data = datap;
    datap = NULL;
    memset((*data) + len_tmp - n, 0, n);
    (*data)[len_tmp - n] |= 0x80;
    *len = len_tmp;

    return ret;
}

int ANSI_X923_Padding(uint8_t *data, int len)
{
    int ret;

    return ret;
}

//------------------------------
//-------AES Operate Mode-------
//------------------------------
int aes_encrypt_ecb(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, int enc)
{
    int ret, l = 0;
    uint8_t *d = malloc(len);
    memcpy(d, data, len);
    l = len;

    while (l)
    {
        if (enc == 1)
        {
            aes_encrypt(mode, d, key);
        }
        else
        {
            aes_equ_decrypt(mode, d, key);
        }
        if (l <= 16)
        {
            break;
        }
        l -= 16;
        d += 16;
    }
    memcpy(data, &d[16 - len], len);
    free(&d[16 - len]);

    return ret;
}

/**
 * AES Cipher Block Chainning Mode
 */
int aes_encrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv)
{
    int ret = 0;
    uint8_t *d;      //data block
    uint8_t *i;      //input block
    uint8_t *c;      //cipher block (unused, aes_encrypt return data from i's address)
    uint8_t *iv_tmp; //iv
    int len_tmp = len;

    int n;           //counter, from 0 to 31
    d = malloc(len);
    memcpy(d, data, len);
    iv_tmp = malloc(len);
    memcpy(iv_tmp, iv, 16);
    i = malloc(len);

    while (len_tmp)
    {
        //iv xor data block
        for (n = 0; n < 16 && n < len_tmp; n++)
        {
            i[n] = d[n] ^ iv_tmp[n];
        }
        //this round's cipher equ next round's iv
        //so prepare it, the n is next round's index
        for (; n < 16; n++)
        {
            i[n] = iv_tmp[n];
        }
        aes_encrypt(mode, i, key);
        //we don't use cipher var, after encrypt i has been updated
        iv_tmp = i;
        if (len_tmp <= 16)
        {
            break;
        }
        len_tmp -= 16; //control the circle
        d += 16; //pointer address add
        i += 16; //pointer address add
    }

    memcpy(data, &i[16 - len], len);

    return ret;
}

/**
 * AES Cipher Block Chainning Decrypt
 * decryption can be performed in parallel
 */
int aes_decrypt_cbc(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv)
{
    int ret = 0;
    uint8_t *d; // data
    uint8_t *i; // input
    uint8_t *iv_tmp; // iv tmp
    int len_tmp = len;

    d = malloc(len);
    i = malloc(len);
    memcpy(i, data, len);
    iv_tmp = malloc(len);
    memcpy(iv_tmp, iv, 16);
    memcpy(iv_tmp + 16, data, len - 16); // perpare iv

    while (len_tmp)
    {
        aes_equ_decrypt(mode, i, key);
        for (int n = 0; n < 16; n++)
        {
            d[n] = i[n] ^ iv_tmp[n];
        }
        if (len_tmp <= 16)
        {
            break;
        }
        len_tmp -= 16;
        d += 16;
        i += 16;
        iv_tmp += 16;
    }

    memcpy(data, &d[16 - len], len);
    // free(&d[16 - len]);

    return ret;
}

/**
 * Cipher Feedback Mode
 * 128 bits shift, next round input equ cipher
 * no need padding
 * also called full-block CFB
 * enc is encrypt flag, 0-decrypt 1-encrypt
 */
int aes_encrypt_cfb128(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key,
                       uint8_t *iv, int *num, int enc)
{
    int ret = 0;
    int n, l = 0;
    uint8_t *iv_tmp;
    uint8_t *cipher;

    cipher = malloc(len);
    iv_tmp = malloc(16);
    if (cipher == NULL || iv_tmp == NULL)
    {
        printf("malloc failed\n");
        return -1;
    }
    memcpy(iv_tmp, iv, 16);

    n = *num; // data len check

    while (l < len)
    {
        if (n == 0)
        {
            aes_encrypt(mode, iv_tmp, key);
        }
        if (enc)
        {
            cipher[l] = iv_tmp[n] ^= data[l];
        }
        else
        {
            cipher[l] = iv_tmp[n] ^ data[l];
            iv_tmp[n] = data[l];
        }
        l++;
        n = (n + 1) % 16;
        *num = n;
    }
    memcpy(data, cipher, len);

    free(cipher);
    free(iv_tmp);
    cipher = NULL;
    iv_tmp = NULL;

    return 0;
}

int aes_encrypt_cfb_s_shift()
{
    return 0;
}

int aes_encrypt_cfb1()
{
    int ret = 0;

    return ret;
}

/**
 * cfb 8 bits shift
 * NOT FINISH, DRAFT
 * 
 */
int aes_encrypt_cfb8(AES_CYPHER_T mode, uint8_t *data, int len, uint8_t *key,
                     uint8_t *iv, int s)
{
    int ret = 0;
    int n, l = 0;
    s /= 8;
    uint8_t *iv_tmp = malloc(32 + 1);
    memcpy(iv_tmp, iv, 16);
    memcpy(iv_tmp + 16, iv, 16);
    uint8_t bits;

    while (l < len)
    {
        if (l == 0 || l % s == 0)
        {
            aes_encrypt(mode, iv_tmp, key);
            bits = iv_tmp[0] ^ data[l];
            printf("%02x\n", bits);
            iv_tmp[32] = bits;
            //shift 8 bits
            for (int i = 16; i < 32; i++)
            {
                iv_tmp[i] = iv_tmp[i + 1];
            }
            memcpy(iv_tmp, &iv_tmp[16], 16);
        }
        l++;
    }

    free(iv_tmp);
    iv_tmp = NULL;

    return ret;
}

int main1()
{
    printf("%02x", aes_mul(0x57, 0x83));
    return 0;
}

int main()
{
#if 0
    uint8_t anni_buf[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    uint8_t anni_buf1[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
                           0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
                           0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
                           0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
                           0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    uint8_t anni_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    uint8_t key_192[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

    uint8_t key_256[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    uint8_t buf[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    uint8_t buf1[14][4] = {0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae,
                           0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5};
    uint8_t roundkey[4 * 4 * 15] = {0};

    uint8_t inputkey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
#endif
                        
#if 0

    for (int ii = 0; ii < 4; ii++)
    {
        for (int jj = 0; jj < 4; jj++)
        {
            printf("%02x ", buf[jj * 4 + ii]);
        }
        printf("\r\n");
    }
    printf("final result\n");
    // aes_key_expansion(AES_CYPHER_128, inputkey, roundkey);
    aes_key_expansion(AES_CYPHER_128, anni_key, roundkey);
    // aes_mix_columns(AES_CYPHER_128, (uint8_t *)buf);
    
    for (int kk = 0; kk <= 10; kk++)
    {
        for (int ii = 0; ii < 4; ii++)
        {
            for (int jj = 0; jj < 4; jj++)
            {
                printf("%02x ", roundkey[kk * 16 + jj * 4 + ii]);
            }
            printf("\r\n");
        }
        printf("\r\n");
    }

    // aes_encrypt(AES_CYPHER_128, anni_buf, anni_key);
    // aes_encrypt(AES_CYPHER_192, anni_buf, key_192);

    // aes_equ_decrypt(AES_CYPHER_128, anni_buf, anni_key);
    // aes_equ_decrypt(AES_CYPHER_192, anni_buf, key_192);

#endif

#define AES_ECB
#ifdef AES_ECB
#include "test.h"
    char buf[] = "so we want add more test data: this is a test message!!";
    uint8_t anni_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    // uint8_t *anni_buf = malloc(sizeof(buf));
    // memcpy(anni_buf, buf, sizeof(buf));
    // int len = sizeof(buf);
    int len = sizeof(pic);
    printf("len is %d\n", len);
    uint8_t *anni_buf = malloc(len);
    memcpy(anni_buf, pic, len);
    
    if (BytePadding(&anni_buf, &len) < 0)
    {
        printf("padding failed\n");
        free(anni_buf);
        anni_buf = NULL;
        return 0;
    }
    printf("len is %d, address is %p\n", len, anni_buf);
    return 0;

    aes_encrypt_ecb(AES_CYPHER_128, anni_buf, len, anni_key, 1);
    // aes_encrypt_ecb(AES_CYPHER_128, anni_buf, len, anni_key, 0);

    uint8_t out[16];
    FILE *fp;
    fp = fopen("./out.txt", "w");

    for (int i = 0; i < sizeof(pic); i += 3)
    {
        fprintf(fp, "%d, %d, %d\n", anni_buf[i], anni_buf[i + 1], anni_buf[i + 2]);
    }
    printf("\n");
    fclose(fp);

#endif

// #define AES_CBC
#ifdef AES_CBC
    // uint8_t anni_buf1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    //                       0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    char buf[] = "this is a test message!!";
    uint8_t *anni_buf = malloc(sizeof(buf));
    memcpy(anni_buf, buf, sizeof(buf));
    int len = sizeof(buf);
    BytePadding(anni_buf, &len);
    // return 0;
    uint8_t anni_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char iv[] = {1,2,3,4,5,6,7,8,8,7,6,5,4,3,2,1};

    aes_encrypt_cbc(AES_CYPHER_128, anni_buf, len, anni_key, iv);
    // aes_encrypt_cbc(AES_CYPHER_192, anni_buf1, sizeof(anni_buf1), key_192, iv);
    
    aes_decrypt_cbc(AES_CYPHER_128, anni_buf, len, anni_key, iv);
    // aes_decrypt_cbc(AES_CYPHER_192, anni_buf1, sizeof(anni_buf1), key_192, iv);
    for (int i = 0; i < sizeof(buf); i++)
    {
        printf("%c", anni_buf[i]);
    }
    printf("\n");
#endif

// #define AES_CBC2
#ifdef AES_CBC2
#include "test.h"
    // uint8_t anni_buf1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    //                       0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    char buf[] = "this is a test message!!";
    int len = sizeof(pic);
    uint8_t *anni_buf = malloc(len);
    memcpy(anni_buf, pic, len);
    BytePadding(anni_buf, &len);
    // return 0;
    uint8_t anni_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char iv[] = {1,2,3,4,5,6,7,8,8,7,6,5,4,3,2,1};

    aes_encrypt_cbc(AES_CYPHER_128, anni_buf, len, anni_key, iv);
    // aes_encrypt_cbc(AES_CYPHER_192, anni_buf1, sizeof(anni_buf1), key_192, iv);
    
    // aes_decrypt_cbc(AES_CYPHER_128, anni_buf, len, anni_key, iv);
    // aes_decrypt_cbc(AES_CYPHER_192, anni_buf1, sizeof(anni_buf1), key_192, iv);
    uint8_t out[16];
    FILE *fp;
    fp = fopen("./out2.txt", "w");

    for (int i = 0; i < sizeof(pic); i += 3)
    {
        fprintf(fp, "%d, %d, %d\n", anni_buf[i], anni_buf[i + 1], anni_buf[i + 2]);
    }
    printf("\n");
    fclose(fp);

#endif

// #define AES_CFB
#ifdef AES_CFB
    int num = 0;
    uint8_t anni_buf1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                           0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                           0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                           0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                           0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                           0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                           0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    // uint8_t anni_buf1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    //                        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    //                        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    //                        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    //                        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    //                        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    //                        0xf6, 0x9f, 0x24, 0x45};

    char anni_buf2[] = "this is a test message!";
    
    uint8_t key[]       = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    uint8_t key_192[]   = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                           0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                           0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    
    uint8_t iv[]        = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    // // the back value of num should equ len % 16
    // aes_encrypt_cfb128(AES_CYPHER_192, anni_buf1, sizeof(anni_buf1), key_192, iv, &num, 1);
    // for (int ii = 0; ii < sizeof(anni_buf1); ii++)
    // {
    //     printf("%02x ", anni_buf1[ii]);
    // }
    // printf("\n");

    // num = 0;
    // aes_encrypt_cfb128(AES_CYPHER_192, anni_buf1, sizeof(anni_buf1), key_192, iv, &num, 0);
    // for (int ii = 0; ii < sizeof(anni_buf1); ii++)
    // {
    //     printf("%02x ", anni_buf1[ii]);
    // }
    // printf("\n");

    aes_encrypt_cfb8(AES_CYPHER_128, anni_buf1, sizeof(anni_buf1), key, iv, 8);
    
#endif

    return 0;
}
