/* ====================================================================
 *  * Copyright (c) 2008 The OpenSSL Project. All rights reserved.
 *   *
 *    * Rights for redistribution and usage in source and binary
 *     * forms are granted according to the OpenSSL license.
 *      */

#include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif


typedef void (*block128_f) (const unsigned char in[16],
                            unsigned char out[16], const void *key);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block);





#ifdef  __cplusplus
}
#endif
