// Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// ====================================================================
// Written by Tianjia Zhang <tianjia.zhang@linux.alibaba.com> for the
// OpenSSL project. Rights for redistribution and usage in source and
// binary forms are granted according to the License.
// ====================================================================
//

#include "arm_arch.h"

.arch	armv8-a

.text

/* Constants */

.type vpsm4_consts,%object
.align 4
vpsm4_consts:
.Lsm4_sbox:
    .byte 0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7
    .byte 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05
    .byte 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3
    .byte 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99
    .byte 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a
    .byte 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62
    .byte 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95
    .byte 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6
    .byte 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba
    .byte 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8
    .byte 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b
    .byte 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35
    .byte 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2
    .byte 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87
    .byte 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52
    .byte 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e
    .byte 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5
    .byte 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1
    .byte 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55
    .byte 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3
    .byte 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60
    .byte 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f
    .byte 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f
    .byte 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51
    .byte 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f
    .byte 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8
    .byte 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd
    .byte 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0
    .byte 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e
    .byte 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84
    .byte 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20
    .byte 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
.size vpsm4_consts,.-vpsm4_consts


/* Register macros */

#define RTMP0	v8
#define RTMP1	v9
#define RTMP2	v10
#define RTMP3	v11

#define RX0	v12
#define RX1	v13
#define RKEY	v14
#define RIV	v15

/* Helper macros. */

#define PREPARE                                                 \
        adr             x5, .Lsm4_sbox;                         \
        ld1             {v16.16b-v19.16b}, [x5], #64;           \
        ld1             {v20.16b-v23.16b}, [x5], #64;           \
        ld1             {v24.16b-v27.16b}, [x5], #64;           \
        ld1             {v28.16b-v31.16b}, [x5];

#define transpose_4x4(s0, s1, s2, s3)                           \
        zip1            RTMP0.4s, s0.4s, s1.4s;                 \
        zip1            RTMP1.4s, s2.4s, s3.4s;                 \
        zip2            RTMP2.4s, s0.4s, s1.4s;                 \
        zip2            RTMP3.4s, s2.4s, s3.4s;                 \
        zip1            s0.2d, RTMP0.2d, RTMP1.2d;              \
        zip2            s1.2d, RTMP0.2d, RTMP1.2d;              \
        zip1            s2.2d, RTMP2.2d, RTMP3.2d;              \
        zip2            s3.2d, RTMP2.2d, RTMP3.2d;

#define rotate_clockwise_90(s0, s1, s2, s3)                     \
        zip1            RTMP0.4s, s1.4s, s0.4s;                 \
        zip2            RTMP1.4s, s1.4s, s0.4s;                 \
        zip1            RTMP2.4s, s3.4s, s2.4s;                 \
        zip2            RTMP3.4s, s3.4s, s2.4s;                 \
        zip1            s0.2d, RTMP2.2d, RTMP0.2d;              \
        zip2            s1.2d, RTMP2.2d, RTMP0.2d;              \
        zip1            s2.2d, RTMP3.2d, RTMP1.2d;              \
        zip2            s3.2d, RTMP3.2d, RTMP1.2d;

#define ROUND4(round, s0, s1, s2, s3)                           \
        dup             RX0.4s, RKEY.s[round];                  \
        /* rk ^ s1 ^ s2 ^ s3 */                                 \
        eor             RTMP1.16b, s2.16b, s3.16b;              \
        eor             RX0.16b, RX0.16b, s1.16b;               \
        eor             RX0.16b, RX0.16b, RTMP1.16b;            \
                                                                \
        /* sbox, non-linear part */                             \
        movi            RTMP3.16b, #64;  /* sizeof(sbox) / 4 */ \
        tbl             RTMP0.16b, {v16.16b-v19.16b}, RX0.16b;  \
        sub             RX0.16b, RX0.16b, RTMP3.16b;            \
        tbx             RTMP0.16b, {v20.16b-v23.16b}, RX0.16b;  \
        sub             RX0.16b, RX0.16b, RTMP3.16b;            \
        tbx             RTMP0.16b, {v24.16b-v27.16b}, RX0.16b;  \
        sub             RX0.16b, RX0.16b, RTMP3.16b;            \
        tbx             RTMP0.16b, {v28.16b-v31.16b}, RX0.16b;  \
                                                                \
        /* linear part */                                       \
        shl             RTMP1.4s, RTMP0.4s, #8;                 \
        shl             RTMP2.4s, RTMP0.4s, #16;                \
        shl             RTMP3.4s, RTMP0.4s, #24;                \
        sri             RTMP1.4s, RTMP0.4s, #(32-8);            \
        sri             RTMP2.4s, RTMP0.4s, #(32-16);           \
        sri             RTMP3.4s, RTMP0.4s, #(32-24);           \
        /* RTMP1 = x ^ rol32(x, 8) ^ rol32(x, 16) */            \
        eor             RTMP1.16b, RTMP1.16b, RTMP0.16b;        \
        eor             RTMP1.16b, RTMP1.16b, RTMP2.16b;        \
        /* RTMP3 = x ^ rol32(x, 24) ^ rol32(RTMP1, 2) */        \
        eor             RTMP3.16b, RTMP3.16b, RTMP0.16b;        \
        shl             RTMP2.4s, RTMP1.4s, 2;                  \
        sri             RTMP2.4s, RTMP1.4s, #(32-2);            \
        eor             RTMP3.16b, RTMP3.16b, RTMP2.16b;        \
        /* s0 ^= RTMP3 */                                       \
        eor             s0.16b, s0.16b, RTMP3.16b;

#define SM4_CRYPT_BLK4(b0, b1, b2, b3)                          \
        rev32           b0.16b, b0.16b;                         \
        rev32           b1.16b, b1.16b;                         \
        rev32           b2.16b, b2.16b;                         \
        rev32           b3.16b, b3.16b;                         \
                                                                \
        transpose_4x4(b0, b1, b2, b3);                          \
                                                                \
        mov             x6, 8;                                  \
4:                                                              \
        ld1             {RKEY.4s}, [x0], #16;                   \
        subs            x6, x6, #1;                             \
                                                                \
        ROUND4(0, b0, b1, b2, b3);                              \
        ROUND4(1, b1, b2, b3, b0);                              \
        ROUND4(2, b2, b3, b0, b1);                              \
        ROUND4(3, b3, b0, b1, b2);                              \
                                                                \
        bne             4b;                                     \
                                                                \
        rotate_clockwise_90(b0, b1, b2, b3);                    \
        rev32           b0.16b, b0.16b;                         \
        rev32           b1.16b, b1.16b;                         \
        rev32           b2.16b, b2.16b;                         \
        rev32           b3.16b, b3.16b;                         \
                                                                \
        /* repoint to rkey */                                   \
        sub             x0, x0, #128;

#define ROUND8(round, s0, s1, s2, s3, t0, t1, t2, t3)           \
        /* rk ^ s1 ^ s2 ^ s3 */                                 \
        dup             RX0.4s, RKEY.s[round];                  \
        eor             RTMP0.16b, s2.16b, s3.16b;              \
        mov             RX1.16b, RX0.16b;                       \
        eor             RTMP1.16b, t2.16b, t3.16b;              \
        eor             RX0.16b, RX0.16b, s1.16b;               \
        eor             RX1.16b, RX1.16b, t1.16b;               \
        eor             RX0.16b, RX0.16b, RTMP0.16b;            \
        eor             RX1.16b, RX1.16b, RTMP1.16b;            \
                                                                \
        /* sbox, non-linear part */                             \
        movi            RTMP3.16b, #64;  /* sizeof(sbox) / 4 */ \
        tbl             RTMP0.16b, {v16.16b-v19.16b}, RX0.16b;  \
        tbl             RTMP1.16b, {v16.16b-v19.16b}, RX1.16b;  \
        sub             RX0.16b, RX0.16b, RTMP3.16b;            \
        sub             RX1.16b, RX1.16b, RTMP3.16b;            \
        tbx             RTMP0.16b, {v20.16b-v23.16b}, RX0.16b;  \
        tbx             RTMP1.16b, {v20.16b-v23.16b}, RX1.16b;  \
        sub             RX0.16b, RX0.16b, RTMP3.16b;            \
        sub             RX1.16b, RX1.16b, RTMP3.16b;            \
        tbx             RTMP0.16b, {v24.16b-v27.16b}, RX0.16b;  \
        tbx             RTMP1.16b, {v24.16b-v27.16b}, RX1.16b;  \
        sub             RX0.16b, RX0.16b, RTMP3.16b;            \
        sub             RX1.16b, RX1.16b, RTMP3.16b;            \
        tbx             RTMP0.16b, {v28.16b-v31.16b}, RX0.16b;  \
        tbx             RTMP1.16b, {v28.16b-v31.16b}, RX1.16b;  \
                                                                \
        /* linear part */                                       \
        shl             RX0.4s, RTMP0.4s, #8;                   \
        shl             RX1.4s, RTMP1.4s, #8;                   \
        shl             RTMP2.4s, RTMP0.4s, #16;                \
        shl             RTMP3.4s, RTMP1.4s, #16;                \
        sri             RX0.4s, RTMP0.4s, #(32 - 8);            \
        sri             RX1.4s, RTMP1.4s, #(32 - 8);            \
        sri             RTMP2.4s, RTMP0.4s, #(32 - 16);         \
        sri             RTMP3.4s, RTMP1.4s, #(32 - 16);         \
        /* RX = x ^ rol32(x, 8) ^ rol32(x, 16) */               \
        eor             RX0.16b, RX0.16b, RTMP0.16b;            \
        eor             RX1.16b, RX1.16b, RTMP1.16b;            \
        eor             RX0.16b, RX0.16b, RTMP2.16b;            \
        eor             RX1.16b, RX1.16b, RTMP3.16b;            \
        /* RTMP0/1 ^= x ^ rol32(x, 24) ^ rol32(RX, 2) */        \
        shl             RTMP2.4s, RTMP0.4s, #24;                \
        shl             RTMP3.4s, RTMP1.4s, #24;                \
        sri             RTMP2.4s, RTMP0.4s, #(32 - 24);         \
        sri             RTMP3.4s, RTMP1.4s, #(32 - 24);         \
        eor             RTMP0.16b, RTMP0.16b, RTMP2.16b;        \
        eor             RTMP1.16b, RTMP1.16b, RTMP3.16b;        \
        shl             RTMP2.4s, RX0.4s, #2;                   \
        shl             RTMP3.4s, RX1.4s, #2;                   \
        sri             RTMP2.4s, RX0.4s, #(32 - 2);            \
        sri             RTMP3.4s, RX1.4s, #(32 - 2);            \
        eor             RTMP0.16b, RTMP0.16b, RTMP2.16b;        \
        eor             RTMP1.16b, RTMP1.16b, RTMP3.16b;        \
        /* s0/t0 ^= RTMP0/1 */                                  \
        eor             s0.16b, s0.16b, RTMP0.16b;              \
        eor             t0.16b, t0.16b, RTMP1.16b;

#define SM4_CRYPT_BLK8(b0, b1, b2, b3, b4, b5, b6, b7)          \
        rev32           b0.16b, b0.16b;                         \
        rev32           b1.16b, b1.16b;                         \
        rev32           b2.16b, b2.16b;                         \
        rev32           b3.16b, b3.16b;                         \
        rev32           b4.16b, b4.16b;                         \
        rev32           b5.16b, b5.16b;                         \
        rev32           b6.16b, b6.16b;                         \
        rev32           b7.16b, b7.16b;                         \
                                                                \
        transpose_4x4(b0, b1, b2, b3);                          \
        transpose_4x4(b4, b5, b6, b7);                          \
                                                                \
        mov             x6, 8;                                  \
8:                                                              \
        ld1             {RKEY.4s}, [x0], #16;                   \
        subs            x6, x6, #1;                             \
                                                                \
        ROUND8(0, b0, b1, b2, b3, b4, b5, b6, b7);              \
        ROUND8(1, b1, b2, b3, b0, b5, b6, b7, b4);              \
        ROUND8(2, b2, b3, b0, b1, b6, b7, b4, b5);              \
        ROUND8(3, b3, b0, b1, b2, b7, b4, b5, b6);              \
                                                                \
        bne             8b;                                     \
                                                                \
        rotate_clockwise_90(b0, b1, b2, b3);                    \
        rotate_clockwise_90(b4, b5, b6, b7);                    \
        rev32           b0.16b, b0.16b;                         \
        rev32           b1.16b, b1.16b;                         \
        rev32           b2.16b, b2.16b;                         \
        rev32           b3.16b, b3.16b;                         \
        rev32           b4.16b, b4.16b;                         \
        rev32           b5.16b, b5.16b;                         \
        rev32           b6.16b, b6.16b;                         \
        rev32           b7.16b, b7.16b;                         \
                                                                \
        /* repoint to rkey */                                   \
        sub             x0, x0, #128;


.global vpsm4_crypt_blk8
.type vpsm4_crypt_blk8,%function
.align 3
vpsm4_crypt_blk8:
        /* input:
         *   x0: round key array, CTX
         *   x1: dst
         *   x2: src
         *   w3: nblocks (multiples of 8)
         */
        PREPARE;

.Lcrypt_loop_blk:
        subs            w3, w3, #8;
        bmi             .Lcrypt_end;

        ld1             {v0.16b-v3.16b}, [x2], #64;
        ld1             {v4.16b-v7.16b}, [x2], #64;

        SM4_CRYPT_BLK8(v0, v1, v2, v3, v4, v5, v6, v7);

        st1             {v0.16b-v3.16b}, [x1], #64;
        st1             {v4.16b-v7.16b}, [x1], #64;

        b               .Lcrypt_loop_blk;

.Lcrypt_end:
        ret;
.size vpsm4_crypt_blk8,.-vpsm4_crypt_blk8

.global vpsm4_cbc_dec_blk8
.type vpsm4_cbc_dec_blk8,%function
.align 3
vpsm4_cbc_dec_blk8:
        /* input:
         *   x0: round key array, CTX
         *   x1: dst
         *   x2: src
         *   x3: iv (big endian, 128 bit)
         *   w4: nblocks (multiples of 8)
         */
        PREPARE;

        ld1             {RIV.16b}, [x3];

.Lcbc_loop_blk:
        subs            w4, w4, #8;
        bmi             .Lcbc_end;

        ld1             {v0.16b-v3.16b}, [x2], #64;
        ld1             {v4.16b-v7.16b}, [x2];

        SM4_CRYPT_BLK8(v0, v1, v2, v3, v4, v5, v6, v7);

        sub             x2, x2, #64;
        eor             v0.16b, v0.16b, RIV.16b;
        ld1             {RTMP0.16b-RTMP3.16b}, [x2], #64;
        eor             v1.16b, v1.16b, RTMP0.16b;
        eor             v2.16b, v2.16b, RTMP1.16b;
        eor             v3.16b, v3.16b, RTMP2.16b;
        st1             {v0.16b-v3.16b}, [x1], #64;

        eor             v4.16b, v4.16b, RTMP3.16b;
        ld1             {RTMP0.16b-RTMP3.16b}, [x2], #64;
        eor             v5.16b, v5.16b, RTMP0.16b;
        eor             v6.16b, v6.16b, RTMP1.16b;
        eor             v7.16b, v7.16b, RTMP2.16b;

        mov             RIV.16b, RTMP3.16b;
        st1             {v4.16b-v7.16b}, [x1], #64;

        b               .Lcbc_loop_blk;

.Lcbc_end:
        /* store new IV */
        st1             {RIV.16b}, [x3];

        ret;
.size vpsm4_cbc_dec_blk8,.-vpsm4_cbc_dec_blk8

.global vpsm4_cfb_dec_blk8
.type vpsm4_cfb_dec_blk8,%function
.align 3
vpsm4_cfb_dec_blk8:
        /* input:
         *   x0: round key array, CTX
         *   x1: dst
         *   x2: src
         *   x3: iv (big endian, 128 bit)
         *   w4: nblocks (multiples of 8)
         */
        PREPARE;

        ld1             {v0.16b}, [x3];

.Lcfb_loop_blk:
        subs            w4, w4, #8;
        bmi             .Lcfb_end;

        ld1             {v1.16b, v2.16b, v3.16b}, [x2], #48;
        ld1             {v4.16b-v7.16b}, [x2];

        SM4_CRYPT_BLK8(v0, v1, v2, v3, v4, v5, v6, v7);

        sub             x2, x2, #48;
        ld1             {RTMP0.16b-RTMP3.16b}, [x2], #64;
        eor             v0.16b, v0.16b, RTMP0.16b;
        eor             v1.16b, v1.16b, RTMP1.16b;
        eor             v2.16b, v2.16b, RTMP2.16b;
        eor             v3.16b, v3.16b, RTMP3.16b;
        st1             {v0.16b-v3.16b}, [x1], #64;

        ld1             {RTMP0.16b-RTMP3.16b}, [x2], #64;
        eor             v4.16b, v4.16b, RTMP0.16b;
        eor             v5.16b, v5.16b, RTMP1.16b;
        eor             v6.16b, v6.16b, RTMP2.16b;
        eor             v7.16b, v7.16b, RTMP3.16b;
        st1             {v4.16b-v7.16b}, [x1], #64;

        mov             v0.16b, RTMP3.16b;

        b               .Lcfb_loop_blk;

.Lcfb_end:
        /* store new IV */
        st1             {v0.16b}, [x3];

        ret;
.size vpsm4_cfb_dec_blk8,.-vpsm4_cfb_dec_blk8

.global vpsm4_ctr_enc_blk8
.type vpsm4_ctr_enc_blk8,%function
.align 3
vpsm4_ctr_enc_blk8:
        /* input:
         *   x0: round key array, CTX
         *   x1: dst
         *   x2: src
         *   x3: ctr (big endian, 128 bit)
         *   w4: nblocks (multiples of 8)
         */
        PREPARE;

        ldp             x7, x8, [x3];
        rev             x7, x7;
        rev             x8, x8;

.Lctr_loop_blk:
        subs            w4, w4, #8;
        bmi             .Lctr_end;

#define inc_le128(vctr)                     \
        mov             vctr.d[1], x8;      \
        mov             vctr.d[0], x7;      \
        adds            x8, x8, #1;         \
        adc             x7, x7, xzr;        \
        rev64           vctr.16b, vctr.16b;

        /* construct CTRs */
        inc_le128(v0);                  /* +0 */
        inc_le128(v1);                  /* +1 */
        inc_le128(v2);                  /* +2 */
        inc_le128(v3);                  /* +3 */
        inc_le128(v4);                  /* +4 */
        inc_le128(v5);                  /* +5 */
        inc_le128(v6);                  /* +6 */
        inc_le128(v7);                  /* +7 */

        SM4_CRYPT_BLK8(v0, v1, v2, v3, v4, v5, v6, v7);

        ld1             {RTMP0.16b-RTMP3.16b}, [x2], #64;
        eor             v0.16b, v0.16b, RTMP0.16b;
        eor             v1.16b, v1.16b, RTMP1.16b;
        eor             v2.16b, v2.16b, RTMP2.16b;
        eor             v3.16b, v3.16b, RTMP3.16b;
        st1             {v0.16b-v3.16b}, [x1], #64;

        ld1             {RTMP0.16b-RTMP3.16b}, [x2], #64;
        eor             v4.16b, v4.16b, RTMP0.16b;
        eor             v5.16b, v5.16b, RTMP1.16b;
        eor             v6.16b, v6.16b, RTMP2.16b;
        eor             v7.16b, v7.16b, RTMP3.16b;
        st1             {v4.16b-v7.16b}, [x1], #64;

        b               .Lctr_loop_blk;

.Lctr_end:
        /* store new CTR */
        rev             x7, x7;
        rev             x8, x8;
        stp             x7, x8, [x3];

        ret;
.size vpsm4_ctr_enc_blk8,.-vpsm4_ctr_enc_blk8
