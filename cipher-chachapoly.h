/* $OpenBSD: cipher-chachapoly.h,v 1.4 2014/06/24 01:13:21 djm Exp $ */

/*
 * Copyright (c) Damien Miller 2013 <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef CHACHA_POLY_AEAD_H
#define CHACHA_POLY_AEAD_H

#include <sys/types.h>

#include <gcrypt.h>

#define CHACHA20_BLOCKSIZE 64

#define POLY1305_KEYLEN 32
#define POLY1305_TAGLEN 16

struct chachapoly_ctx {
	gcry_cipher_hd_t main_hd, header_hd;
	gcry_mac_hd_t mac_hd;
	int initialized;
};

void	chachapoly_free(struct chachapoly_ctx *cpctx);
int	chachapoly_init(struct chachapoly_ctx *cpctx,
    const u_char *key, u_int keylen)
    __attribute__((__bounded__(__buffer__, 2, 3)));
int	chachapoly_crypt(struct chachapoly_ctx *cpctx, u_int seqnr,
    u_char *dest, const u_char *src, u_int len, u_int aadlen, u_int authlen,
    int do_encrypt);
int	chachapoly_get_length(struct chachapoly_ctx *cpctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
    __attribute__((__bounded__(__buffer__, 4, 5)));

#endif /* CHACHA_POLY_AEAD_H */
