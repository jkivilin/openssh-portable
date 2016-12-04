/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD: cipher-chachapoly.c,v 1.7 2015/01/14 10:24:42 markus Exp $ */

#include "includes.h"

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <gcrypt.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"

void chachapoly_free(struct chachapoly_ctx *ctx)
{
	if (ctx->initialized) {
		gcry_cipher_close(ctx->main_hd);
		gcry_cipher_close(ctx->header_hd);
		gcry_mac_close(ctx->mac_hd);
		ctx->initialized = 0;
	}
}

int chachapoly_init(struct chachapoly_ctx *ctx,
    const u_char *key, u_int keylen)
{
	static int gcrypt_initialized;

	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		return SSH_ERR_INVALID_ARGUMENT;

	if (!gcrypt_initialized) {
		if (!gcry_check_version(GCRYPT_VERSION))
			return SSH_ERR_INTERNAL_ERROR;
		gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
		gcrypt_initialized = 1;
	}

	if (!ctx->initialized) {
		/* Open cipher/mac handles. */
		if (gcry_cipher_open(&ctx->main_hd, GCRY_CIPHER_CHACHA20,
				    GCRY_CIPHER_MODE_STREAM, 0))
			return SSH_ERR_INTERNAL_ERROR;
		if (gcry_cipher_open(&ctx->header_hd, GCRY_CIPHER_CHACHA20,
				    GCRY_CIPHER_MODE_STREAM, 0)) {
			gcry_cipher_close(ctx->main_hd);
			return SSH_ERR_INTERNAL_ERROR;
		}
		if (gcry_mac_open(&ctx->mac_hd, GCRY_MAC_POLY1305, 0, NULL)) {
			gcry_cipher_close(ctx->main_hd);
			gcry_cipher_close(ctx->header_hd);
			return SSH_ERR_INTERNAL_ERROR;
		}

		ctx->initialized = 1;
	} else {
		/* Already open, rekeying? */
	}

	if (gcry_cipher_setkey(ctx->main_hd, key, 32))
		goto err_out;
	if (gcry_cipher_setkey(ctx->header_hd, key + 32, 32))
		goto err_out;

	return 0;

 err_out:
	chachapoly_free(ctx);
	return SSH_ERR_INTERNAL_ERROR;
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	u_char seqbuf[8];
	u_char poly_key[CHACHA20_BLOCKSIZE];
	int r = SSH_ERR_INTERNAL_ERROR;
	gcry_error_t ret;

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number, block counter is reset to 0. First 32 bytes
	 * of 64 byte ChaCha20 block are used for Poly1305 key and remaining
	 * 32 bytes are discarded. Block counter is increased to 1.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	POKE_U64(seqbuf, seqnr);
	if (gcry_cipher_setiv(ctx->main_hd, seqbuf, sizeof(seqbuf)))
		goto out;
	if (gcry_cipher_encrypt(ctx->main_hd, poly_key, sizeof(poly_key),
				NULL, 0))
		goto out;
	if (gcry_mac_setkey(ctx->mac_hd, poly_key, POLY1305_KEYLEN))
		goto out;

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		if (gcry_mac_write(ctx->mac_hd, src, aadlen + len))
			goto out;
		ret = gcry_mac_verify(ctx->mac_hd, tag, POLY1305_TAGLEN);
		if (ret == GPG_ERR_CHECKSUM) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		} else if (ret)
			goto out;
	}

	/* Crypt additional data */
	if (aadlen) {
		if (gcry_cipher_setiv(ctx->header_hd, seqbuf, sizeof(seqbuf)))
			goto out;
		if (gcry_cipher_encrypt(ctx->header_hd, dest, aadlen,
					src, aadlen))
			goto out;
	}

	if (do_encrypt) {
		if (gcry_cipher_encrypt(ctx->main_hd, dest + aadlen, len,
					src + aadlen, len))
			goto out;
	} else {
		if (gcry_cipher_decrypt(ctx->main_hd, dest + aadlen, len,
					src + aadlen, len))
			goto out;
	}

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		size_t taglen = POLY1305_TAGLEN;
		if (gcry_mac_write(ctx->mac_hd, dest, aadlen + len))
			goto out;
		if (gcry_mac_read(ctx->mac_hd, dest + aadlen + len, &taglen))
			goto out;
		if (taglen != POLY1305_TAGLEN)
			goto out;
	}
	r = 0;
 out:
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	if (gcry_cipher_setiv(ctx->header_hd, seqbuf, sizeof(seqbuf)))
		return SSH_ERR_INTERNAL_ERROR;
	if (gcry_cipher_decrypt(ctx->header_hd, buf, 4, cp, 4))
		return SSH_ERR_INTERNAL_ERROR;
	*plenp = PEEK_U32(buf);
	return 0;
}
