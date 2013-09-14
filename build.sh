#!/bin/sh
#
# Copyright (C) 2011 Gregor Pintar <grpintar@gmail.com>
#
# Permission is granted to deal in this work without any restriction,
# including unlimited rights to use, publicly perform, publish,
# reproduce, relicence, modify, merge, and/or distribute in any form,
# for any purpose, with or without fee, and by any means.
#
# This work is provided "AS IS" and WITHOUT WARRANTY of any kind,
# to the utmost extent permitted by applicable law. In no event
# shall a licensor, author or contributor be held liable for any
# issues arising in any way out of dealing in the work.

CC=${CC:-"cc"}
AR=${AR:-"ar"}
STRIP=${STRIP:-"strip"}
CFLAGS="-std=c99 -pedantic -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -I include/ -fPIC -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $CFLAGS"
# -fstack-protector-all -fno-strict-aliasing -Werror  Wc++-compat -Wcast-align -DNDEBUG -fwhole-program -ffunction-sections -fdata-sections
OPTIM="-O2 -D_FORTIFY_SOURCE=2 -flto -DNDEBUG $OPTIM"
LDFLAGS="-Wall -lm $LDFLAGS"

SRC="lib/version.c lib/authstream.c lib/authstream/eax.c lib/mac.c lib/mac/hmac.c lib/mac/omac.c lib/stream/salsa20.c lib/hash/blake256.c lib/hash/blake512.c lib/hash/blake2s.c lib/hash/blake2b.c lib/hash/keccak1600.c lib/hash/keccak800.c lib/block/xtea.c lib/block/threefish256.c lib/block/threefish512.c lib/block/threefish1024.c lib/stream/ecb.c lib/stream/ctr.c lib/stream/cbc.c lib/stream/ofb.c lib/stream/rc4.c lib/stream/chacha.c lib/block/rijndael.c lib/block/serpent.c lib/block/rc6.c lib/block/twofish.c lib/block/blowfish.c lib/block/anubis.c lib/block/noekeon.c lib/block/aria.c lib/block/seed.c lib/block/camellia.c lib/block/gost.c lib/hash.c lib/hash/sha1.c lib/hash/sha2_256.c lib/hash/sha2_512.c lib/memwipe.c lib/random.c lib/pkcs7.c lib/block.c lib/stream.c lib/pbkdf2.c lib/scrypt.c lib/stream/cfb.c"
OBJ="version.o authstream.o eax.o mac.o hmac.o omac.o salsa20.o blake256.o blake512.o blake2s.o blake2b.o keccak1600.o keccak800.o xtea.o threefish256.o threefish512.o threefish1024.o ecb.o ctr.o cbc.o ofb.o rc4.o chacha.o rijndael.o serpent.o rc6.o twofish.o blowfish.o anubis.o noekeon.o aria.o seed.o camellia.o gost.o hash.o sha1.o sha2_256.o sha2_512.o memwipe.o random.o pkcs7.o block.o stream.o pbkdf2.o scrypt.o cfb.o"

i=1
while [ $i -le $# ]; do

	eval param=\$$i;

	case $param in
	"-g")
		debug=1
		;;
	"-shared")
		shared=1
		;;
	"-os=unix")
		os=1
		CFLAGS="$CFLAGS -DKRIPTO_UNIX"
		;;
	"-os=windows")
		os=2
		CFLAGS="$CFLAGS -DKRIPTO_WINDOWS"
		#LDFLAGS="$LDFLAGS -Wl,-subsystem,windows"
		;;
	"-h" | "--help")
		echo "-g		 		Debug build"
		echo "-shared		 		Build shared library"
		echo "-os=[unix|windows]		Target operating system"
		exit 1
		;;
	*)
		CFLAGS="$CFLAGS $param"
		;;
	esac

	i=$(($i+1))
done

# if OS not defined assume UNIX
if [ -z $os ]; then
	CFLAGS="$CFLAGS -DKRIPTO_UNIX"
fi

if [ -z $debug ]; then
	CFLAGS="$CFLAGS $OPTIM"
	LDFLAGS="$LDFLAGS $OPTIM"
else
	CFLAGS="$CFLAGS -g -fstack-protector-all"
fi

# compile
$PREFIX$CC -c $SRC $CFLAGS

# build static
$PREFIX$AR rcs libkripto.a $OBJ
# strip
#if [ -z $debug ]; then
#	$PREFIX$STRIP -s libkripto.a
#fi

# build shared
if [ ! -z $shared ]; then
	$PREFIX$CC -shared $LDFLAGS -Wl,-soname,libkripto.so.0 -o libkripto.so.0.1.0 $OBJ -lc

	# strip
	#if [ -z $debug ]; then
	#	$PREFIX$STRIP -s libkripto.so.*
	#fi
fi

# clean
rm -f *.o
