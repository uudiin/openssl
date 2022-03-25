/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_sm4.h"

static int cipher_hw_sm4_initkey(PROV_CIPHER_CTX *ctx,
                                 const unsigned char *key, size_t keylen)
{
    PROV_SM4_CTX *sctx =  (PROV_SM4_CTX *)ctx;
    SM4_KEY *ks = &sctx->ks.ks;

    ctx->ks = ks;
    if (ctx->enc
            || (ctx->mode != EVP_CIPH_ECB_MODE
                && ctx->mode != EVP_CIPH_CBC_MODE)) {
#ifdef HWSM4_CAPABLE
        if (HWSM4_CAPABLE) {
            HWSM4_set_encrypt_key(key, ks);
            ctx->block = (block128_f)HWSM4_encrypt;
            ctx->stream.cbc = NULL;
#ifdef HWSM4_cbc_encrypt
            if (ctx->mode == EVP_CIPH_CBC_MODE)
                ctx->stream.cbc = (cbc128_f)HWSM4_cbc_encrypt;
            else
#endif
#ifdef HWSM4_ecb_encrypt
            if (ctx->mode == EVP_CIPH_ECB_MODE)
                ctx->stream.ecb = (ecb128_f)HWSM4_ecb_encrypt;
            else
#endif
#ifdef HWSM4_ctr32_encrypt_blocks
            if (ctx->mode == EVP_CIPH_CTR_MODE)
                ctx->stream.ctr = (ctr128_f)HWSM4_ctr32_encrypt_blocks;
            else
#endif
            (void)0;            /* terminate potentially open 'else' */
        } else
#endif
        {
            ossl_sm4_set_key(key, ks);
            ctx->block = (block128_f)ossl_sm4_encrypt;
        }
    } else {
#ifdef HWSM4_CAPABLE
        if (HWSM4_CAPABLE) {
            HWSM4_set_decrypt_key(key, ks);
            ctx->block = (block128_f)HWSM4_decrypt;
            ctx->stream.cbc = NULL;
#ifdef HWSM4_cbc_encrypt
            if (ctx->mode == EVP_CIPH_CBC_MODE)
                ctx->stream.cbc = (cbc128_f)HWSM4_cbc_encrypt;
#endif
#ifdef HWSM4_ecb_encrypt
            if (ctx->mode == EVP_CIPH_ECB_MODE)
                ctx->stream.ecb = (ecb128_f)HWSM4_ecb_encrypt;
#endif
        } else
#endif
        {
            ossl_sm4_set_key(key, ks);
            ctx->block = (block128_f)ossl_sm4_decrypt;
        }
    }

    return 1;
}

IMPLEMENT_CIPHER_HW_COPYCTX(cipher_hw_sm4_copyctx, PROV_SM4_CTX)

#if defined(VPSM4_CAPABLE) && !defined(HWSM4_CAPABLE)

#define BYTES2BLK8(nbytes)  (((nbytes) >> 4) & ~(8 - 1))

int cipher_hw_vpsm4_cbc(PROV_CIPHER_CTX *dat, unsigned char *out,
                        const unsigned char *in, size_t len)
{
    if (dat->enc) {
        CRYPTO_cbc128_encrypt(in, out, len, dat->ks, dat->iv, dat->block);
    } else {
        size_t blks = BYTES2BLK8(len);

        if (blks) {
            vpsm4_cbc_dec_blk8(dat->ks.rk, out, in, dat->iv, blks);
            in += blks * 16;
            out += blks * 16;
            len -= blks * 16;
        }

        if (len)
            CRYPTO_cbc128_decrypt(in, out, len, dat->ks, dat->iv, dat->block);
    }

    return 1;
}

int cipher_hw_vpsm4_ecb(PROV_CIPHER_CTX *dat, unsigned char *out,
                        const unsigned char *in, size_t len)
{
    size_t i, bl = dat->blocksize;
    size_t blks;

    if (len < bl)
        return 1;

    blks = BYTES2BLK8(len);
    if (blks) {
        vpsm4_crypt_blk8(dat->ks.rk, out, in, blks);
        in += blks * 16;
        out += blks * 16;
        len -= blks * 16;
    }

    if (len) {
        for (i = 0, len -= bl; i <= len; i += bl)
            (*dat->block) (in + i, out + i, dat->ks);
    }

    return 1;
}

int cipher_hw_vpsm4_cfb128(PROV_CIPHER_CTX *dat, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    int num = dat->num;

    if (dat->enc) {
        CRYPTO_cfb128_encrypt(in, out, len, dat->ks, dat->iv, &num, dat->enc,
                              dat->block);
    } else {
        size_t blks = BYTES2BLK8(len);

        if (blks) {
            vpsm4_cfb_dec_blk8(dat->ks.rk, out, in, dat->iv, blks);
            in += blks * 16;
            out += blks * 16;
            len -= blks * 16;
        }

        if (len)
            CRYPTO_cfb128_encrypt(in, out, len, dat->ks, dat->iv, &num,
                                  dat->enc, dat->block);
    }

    dat->num = num;

    return 1;
}

int cipher_hw_vpsm4_ctr(PROV_CIPHER_CTX *dat, unsigned char *out,
                        const unsigned char *in, size_t len)
{
    unsigned int num = dat->num;
    size_t blks;

    while (num && len) {
        *(out++) = *(in++) ^ dat->buf[num];
        --len;
        num = (num + 1) % 16;
    }

    blks = BYTES2BLK8(len);
    if (blks) {
        vpsm4_ctr_enc_blk8(dat->ks.rk, out, in, dat->iv, blks);
        in += blks * 16;
        out += blks * 16;
        len -= blks * 16;
    }

    if (len)
        CRYPTO_ctr128_encrypt(in, out, len, dat->ks, dat->iv, dat->buf,
                              &num, dat->block);
    dat->num = num;

    return 1;
}

#endif

# define PROV_CIPHER_HW_sm4_mode(mode, cipher)                                 \
static const PROV_CIPHER_HW sm4_##mode = {                                     \
    cipher_hw_sm4_initkey,                                                     \
    cipher,                                                                    \
    cipher_hw_sm4_copyctx                                                      \
};                                                                             \
const PROV_CIPHER_HW *ossl_prov_cipher_hw_sm4_##mode(size_t keybits)           \
{                                                                              \
    return &sm4_##mode;                                                        \
}

#if defined(VPSM4_CAPABLE) && !defined(HWSM4_CAPABLE)
PROV_CIPHER_HW_sm4_mode(cbc, cipher_hw_vpsm4_cbc)
PROV_CIPHER_HW_sm4_mode(ecb, cipher_hw_vpsm4_ecb)
PROV_CIPHER_HW_sm4_mode(cfb128, cipher_hw_vpsm4_cfb128)
PROV_CIPHER_HW_sm4_mode(ctr, cipher_hw_vpsm4_ctr)
#else
PROV_CIPHER_HW_sm4_mode(cbc, ossl_cipher_hw_generic_cbc)
PROV_CIPHER_HW_sm4_mode(ecb, ossl_cipher_hw_generic_ecb)
PROV_CIPHER_HW_sm4_mode(cfb128, ossl_cipher_hw_generic_cfb128)
PROV_CIPHER_HW_sm4_mode(ctr, ossl_cipher_hw_generic_ctr)
#endif
PROV_CIPHER_HW_sm4_mode(ofb128, ossl_cipher_hw_generic_ofb128)
