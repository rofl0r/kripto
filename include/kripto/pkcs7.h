#ifndef KRIPTO_PKCS7_H
#define KRIPTO_PKCS7_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

extern size_t kripto_pkcs7_add(void *buf, const size_t len, unsigned int pad, const size_t maxlen);
extern size_t kripto_pkcs7_rem(void *buf, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
