#!/bin/sh

CFLAGS="libkripto.a -std=c99 -pedantic -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -I include/ -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $CFLAGS"

#cc test/mac/hmac.c $CFLAGS -o t
#./t

cc test/pbkdf2.c $CFLAGS -o t
./t

#cc test/block/rijndael256.c $CFLAGS -o t
#./t

#cc test/block/xtea.c $CFLAGS -o t
#./t

#cc test/block/blowfish.c $CFLAGS -o t
#./t

#cc test/block/serpent.c $CFLAGS -o t
#./t

#cc test/block/camellia.c $CFLAGS -o t
#./t

#cc test/block/threefish.c $CFLAGS -o t
#./t

#cc test/hash/sha2.c $CFLAGS -o t
#./t

#cc test/hash/blake256.c $CFLAGS -o t
#./t

#cc test/hash/blake2b.c $CFLAGS -o t
#./t

#cc test/hash/keccak1600.c $CFLAGS -o t
#./t

#cc test/stream/chacha.c $CFLAGS -o t
#./t

#cc test/stream/rc4i.c $CFLAGS -o t
#./t

#cc test/stream/rc4.c $CFLAGS -o t
#./t

#cc test/stream/salsa20.c $CFLAGS -o t
#./t

#cc test/mode/ctr.c $CFLAGS -o t
#./t

rm t
