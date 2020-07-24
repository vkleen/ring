/*
 * Copyright 2009-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* This file is derived from ppccap.c in OpenSSL */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/utsname.h>

# define PPC_FPU64       (1<<0)
# define PPC_ALTIVEC     (1<<1)
# define PPC_CRYPTO207   (1<<2)
# define PPC_FPU         (1<<3)
# define PPC_MADD300     (1<<4)
# define PPC_MFTB        (1<<5)
# define PPC_MFSPR268    (1<<6)

unsigned int GFp_ppccap_P = 0;

int bn_mul_mont_int(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                    const unsigned long *np, const unsigned long *n0, int num);
int bn_mul4x_mont_int(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                      const unsigned long *np, const unsigned long *n0, int num);
int GFp_bn_mul_mont(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                const unsigned long *np, const unsigned long *n0, int num)
{
    if (num < 4)
        return 0;

    if ((num & 3) == 0)
        return bn_mul4x_mont_int(rp, ap, bp, np, n0, num);

    /*
     * There used to be [optional] call to bn_mul_mont_fpu64 here,
     * but above subroutine is faster on contemporary processors.
     * Formulation means that there might be old processors where
     * FPU code path would be faster, POWER6 perhaps, but there was
     * no opportunity to figure it out...
     */

    return bn_mul_mont_int(rp, ap, bp, np, n0, num);
}


void ChaCha20_ctr32_int(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void ChaCha20_ctr32_vmx(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void ChaCha20_ctr32_vsx(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void GFp_ChaCha20_ctr32(unsigned char *out, const unsigned char *inp,
                    size_t len, const unsigned int key[8],
                    const unsigned int counter[4])
{
    /* ring does not check and vsx ver crashes with 0-length input */
    if (!len)
        return;
    (GFp_ppccap_P & PPC_CRYPTO207)
        ? ChaCha20_ctr32_vsx(out, inp, len, key, counter)
        : GFp_ppccap_P & PPC_ALTIVEC
            ? ChaCha20_ctr32_vmx(out, inp, len, key, counter)
            : ChaCha20_ctr32_int(out, inp, len, key, counter);
}


void GFp_poly1305_init_int(void *ctx, const unsigned char key[16]);
void GFp_poly1305_blocks(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void GFp_poly1305_emit(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
void GFp_poly1305_init_fpu(void *ctx, const unsigned char key[16]);
void GFp_poly1305_blocks_fpu(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void GFp_poly1305_emit_fpu(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
void GFp_poly1305_blocks_vsx(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
int GFp_poly1305_init_asm(void *ctx, const unsigned char key[16], void *func[2]);

int GFp_poly1305_init_asm(void *ctx, const unsigned char key[16], void *func[2])
{
    if (GFp_ppccap_P & PPC_CRYPTO207) {
        GFp_poly1305_init_int(ctx, key);
        func[0] = (void*)(uintptr_t)GFp_poly1305_blocks_vsx;
        func[1] = (void*)(uintptr_t)GFp_poly1305_emit;
    } else if (sizeof(size_t) == 4 && (GFp_ppccap_P & PPC_FPU)) {
        GFp_poly1305_init_fpu(ctx, key);
        func[0] = (void*)(uintptr_t)GFp_poly1305_blocks_fpu;
        func[1] = (void*)(uintptr_t)GFp_poly1305_emit_fpu;
    } else {
        GFp_poly1305_init_int(ctx, key);
        func[0] = (void*)(uintptr_t)GFp_poly1305_blocks;
        func[1] = (void*)(uintptr_t)GFp_poly1305_emit;
    }
    return 1;
}
