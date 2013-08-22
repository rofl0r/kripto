#ifndef KRIPTO_MAC_HMAC_H
#define KRIPTO_MAC_HMAC_H

#include <kripto/mac.h>
#include <kripto/hash.h>

extern kripto_mac_desc *kripto_mac_hmac(const kripto_hash_desc *hash);

#endif
