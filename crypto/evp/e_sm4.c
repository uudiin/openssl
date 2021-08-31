/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_SM4
# include <openssl/evp.h>
# include <openssl/modes.h>
# include <openssl/rand.h>
# include "crypto/sm4.h"
# include "crypto/evp.h"
# include "crypto/modes.h"
# include "evp_local.h"

typedef struct {
    SM4_KEY ks;
} EVP_SM4_KEY;

typedef struct {
    union {
        OSSL_UNION_ALIGN;
        SM4_KEY ks;
    } ks;                       /* SM4 subkey to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
} EVP_SM4_GCM_CTX;

typedef struct {
    union {
        OSSL_UNION_ALIGN;
        SM4_KEY ks;
    } ks;                       /* SM4 key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    int tag_set;                /* Set if tag is valid */
    int len_set;                /* Set if message length set */
    int L, M;                   /* L and M parameters from RFC3610 */
    int tls_aad_len;            /* TLS AAD length */
    CCM128_CONTEXT ccm;
    ccm128_f str;
} EVP_SM4_CCM_CTX;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    ossl_sm4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static void sm4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const SM4_KEY *key,
                            unsigned char *ivec, const int enc)
{
    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f)ossl_sm4_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f)ossl_sm4_decrypt);
}

static void sm4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                               size_t length, const SM4_KEY *key,
                               unsigned char *ivec, int *num, const int enc)
{
    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f)ossl_sm4_encrypt);
}

static void sm4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                            const SM4_KEY *key, const int enc)
{
    if (enc)
        ossl_sm4_encrypt(in, out, key);
    else
        ossl_sm4_decrypt(in, out, key);
}

static void sm4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                               size_t length, const SM4_KEY *key,
                               unsigned char *ivec, int *num)
{
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num,
                          (block128_f)ossl_sm4_encrypt);
}

IMPLEMENT_BLOCK_CIPHER(sm4, ks, sm4, EVP_SM4_KEY, NID_sm4,
                       16, 16, 16, 128, EVP_CIPH_FLAG_DEFAULT_ASN1,
                       sm4_init_key, 0, 0, 0, 0)

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int n = EVP_CIPHER_CTX_get_num(ctx);
    unsigned int num;
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY, ctx);

    if (n < 0)
        return 0;
    num = (unsigned int)n;

    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks, ctx->iv,
                          EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                          (block128_f)ossl_sm4_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static const EVP_CIPHER sm4_ctr_mode = {
    NID_sm4_ctr, 1, 16, 16,
    EVP_CIPH_CTR_MODE,
    EVP_ORIG_GLOBAL,
    sm4_init_key,
    sm4_ctr_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_ctr(void)
{
    return &sm4_ctr_mode;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int sm4_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, ctx);

    if (!iv && !key)
        return 1;

    if (key) {
        ossl_sm4_set_key(key, &gctx->ks.ks);
        CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks, (block128_f)ossl_sm4_encrypt);

        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

static int sm4_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, ctx);

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_get_iv_length(ctx->cipher);
        gctx->iv = ctx->iv;
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != ctx->iv)
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL) {
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_is_encrypting(ctx))
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_is_encrypting(ctx)
            || gctx->taglen < 0)
            return 0;
        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (EVP_CIPHER_CTX_is_encrypting(ctx)
            && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0
            || EVP_CIPHER_CTX_is_encrypting(ctx))
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len =
                EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 1];
            /* Correct length for explicit IV */
            if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_is_encrypting(ctx)) {
                if (len < EVP_GCM_TLS_TAG_LEN)
                    return 0;
                len -= EVP_GCM_TLS_TAG_LEN;
            }
            EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_GCM_CTX *gctx_out = EVP_C_DATA(EVP_SM4_GCM_CTX,out);
            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == ctx->iv)
                gctx_out->iv = out->iv;
            else {
                if ((gctx_out->iv = OPENSSL_malloc(gctx->ivlen)) == NULL) {
                    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
        }
        return 1;

    default:
        return -1;
    }
}

static int sm4_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, ctx);
    int rv = -1;

    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CIPHER_CTX_is_encrypting(ctx) ?
                            EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
        /* Encrypt payload */
        if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
            goto err;
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
            goto err;
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
                          EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(EVP_CIPHER_CTX_buf_noconst(ctx), in + len,
                          EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, ctx);

    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return sm4_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;

    if (in) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
            if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
                return -1;
        } else {
            if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
                return -1;
        }
        return len;
    } else {
        if (!EVP_CIPHER_CTX_is_encrypting(ctx)) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm,
                                     EVP_CIPHER_CTX_buf_noconst(ctx),
                                     gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }
}

static int sm4_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, ctx);

    if (gctx->iv != ctx->iv)
        OPENSSL_free(gctx->iv);

    return 1;
}

#define SM4_AUTH_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                         | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                         | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_AEAD_CIPHER \
                         | EVP_CIPH_CUSTOM_IV_LENGTH)


static const EVP_CIPHER sm4_gcm_mode = {
    NID_sm4_gcm, 1, 16, 12,
    SM4_AUTH_FLAGS | EVP_CIPH_GCM_MODE,
    EVP_ORIG_GLOBAL,
    sm4_gcm_init_key,
    sm4_gcm_cipher,
    sm4_gcm_cleanup,
    sizeof(EVP_SM4_GCM_CTX),
    NULL, NULL, sm4_gcm_ctrl, NULL
};

const EVP_CIPHER *EVP_sm4_gcm(void)
{
    return &sm4_gcm_mode;
}

static int sm4_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX, ctx);

    if (!iv && !key)
        return 1;

    if (key) {
        ossl_sm4_set_key(key, &cctx->ks.ks);
        CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                           &cctx->ks, (block128_f) ossl_sm4_encrypt);
        cctx->str = NULL;
        cctx->key_set = 1;
    }
    if (iv) {
        memcpy(ctx->iv, iv, 15 - cctx->L);
        cctx->iv_set = 1;
    }
    return 1;
}

static int sm4_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX, ctx);

    switch (type) {
    case EVP_CTRL_INIT:
        cctx->key_set = 0;
        cctx->iv_set = 0;
        cctx->L = 8;
        cctx->M = 12;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        cctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = 15 - cctx->L;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        cctx->tls_aad_len = arg;
        {
            uint16_t len =
                EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 1];
            /* Correct length for explicit IV */
            if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_is_encrypting(ctx)) {
                if (len < cctx->M)
                    return 0;
                len -= cctx->M;
            }
            EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(ctx)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return cctx->M;

    case EVP_CTRL_CCM_SET_IV_FIXED:
        /* Sanity check length */
        if (arg != EVP_CCM_TLS_FIXED_IV_LEN)
            return 0;
        /* Just copy to first part of IV */
        memcpy(ctx->iv, ptr, arg);
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        arg = 15 - arg;
        /* fall thru */
    case EVP_CTRL_CCM_SET_L:
        if (arg < 2 || arg > 8)
            return 0;
        cctx->L = arg;
        return 1;
    case EVP_CTRL_AEAD_SET_TAG:
        if ((arg & 1) || arg < 4 || arg > 16)
            return 0;
        if (EVP_CIPHER_CTX_is_encrypting(ctx) && ptr)
            return 0;
        if (ptr) {
            cctx->tag_set = 1;
            memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
        }
        cctx->M = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (!EVP_CIPHER_CTX_is_encrypting(ctx) || !cctx->tag_set)
            return 0;
        if (!CRYPTO_ccm128_tag(&cctx->ccm, ptr, (size_t)arg))
            return 0;
        cctx->tag_set = 0;
        cctx->iv_set = 0;
        cctx->len_set = 0;
        return 1;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_CCM_CTX *cctx_out = EVP_C_DATA(EVP_SM4_CCM_CTX, out);
            if (cctx->ccm.key) {
                if (cctx->ccm.key != &cctx->ks)
                    return 0;
                cctx_out->ccm.key = &cctx_out->ks;
            }
            return 1;
        }

    default:
        return -1;
    }
}

static int sm4_ccm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX, ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;

    /* Encrypt/decrypt must be performed in place */
    if (out != in || len < (EVP_CCM_TLS_EXPLICIT_IV_LEN + (size_t)cctx->M))
        return -1;
    /* If encrypting set explicit IV from sequence number (start of AAD) */
    if (EVP_CIPHER_CTX_is_encrypting(ctx))
        memcpy(out, EVP_CIPHER_CTX_buf_noconst(ctx),
               EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Get rest of IV from explicit IV */
    memcpy(ctx->iv + EVP_CCM_TLS_FIXED_IV_LEN, in,
           EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Correct length value */
    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx->M;
    if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L,
                            len))
            return -1;
    /* Use saved AAD */
    CRYPTO_ccm128_aad(ccm, EVP_CIPHER_CTX_buf_noconst(ctx),
                      cctx->tls_aad_len);
    /* Fix buffer to point to payload */
    in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
        if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len, cctx->str)
                      : CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        if (!CRYPTO_ccm128_tag(ccm, out + len, cctx->M))
            return -1;
        return len + EVP_CCM_TLS_EXPLICIT_IV_LEN + cctx->M;
    } else {
        if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len, cctx->str)
                      : !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, in + len, cctx->M))
                    return len;
            }
        }
        OPENSSL_cleanse(out, len);
        return -1;
    }
}

static int sm4_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX, ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;

    /* If not set up, return error */
    if (!cctx->key_set)
        return -1;

    if (cctx->tls_aad_len >= 0)
        return sm4_ccm_tls_cipher(ctx, out, in, len);

    /* EVP_*Final() doesn't return any data */
    if (in == NULL && out != NULL)
        return 0;

    if (!cctx->iv_set)
        return -1;

    if (!out) {
        if (!in) {
            if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L, len))
                return -1;
            cctx->len_set = 1;
            return len;
        }
        /* If have AAD need message length */
        if (!cctx->len_set && len)
            return -1;
        CRYPTO_ccm128_aad(ccm, in, len);
        return len;
    }

    /* The tag must be set before actually decrypting data */
    if (!EVP_CIPHER_CTX_is_encrypting(ctx) && !cctx->tag_set)
        return -1;

    /* If not set length yet do it */
    if (!cctx->len_set) {
        if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L, len))
            return -1;
        cctx->len_set = 1;
    }
    if (EVP_CIPHER_CTX_is_encrypting(ctx)) {
        if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len, cctx->str)
                      : CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        cctx->tag_set = 1;
        return len;
    } else {
        int rv = -1;
        if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len,
                                                     cctx->str) :
            !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, EVP_CIPHER_CTX_buf_noconst(ctx),
                                   cctx->M))
                    rv = len;
            }
        }
        if (rv == -1)
            OPENSSL_cleanse(out, len);
        cctx->iv_set = 0;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        return rv;
    }
}

static const EVP_CIPHER sm4_ccm_mode = {
    NID_sm4_ccm, 1, 16, 12,
    SM4_AUTH_FLAGS | EVP_CIPH_CCM_MODE,
    EVP_ORIG_GLOBAL,
    sm4_ccm_init_key,
    sm4_ccm_cipher,
    NULL,
    sizeof(EVP_SM4_CCM_CTX),
    NULL, NULL, sm4_ccm_ctrl, NULL
};

const EVP_CIPHER *EVP_sm4_ccm(void)
{
    return &sm4_ccm_mode;
}

#endif
