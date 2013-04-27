CC = cc
CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wcast-qual -Wbad-function-cast -Wshadow -I include/ -fPIC -D_ANSI_SOURCE -D_ISOC99_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DKRIPTO_UNIX
LDFLAGS = -Wall
OPTIM = -O2 -D_FORTIFY_SOURCE=2 -flto
AR = ar
STRIP = strip
SRC = lib/version.c lib/mac.c lib/mac/hmac.c lib/mode.c lib/block/threefish.c lib/mode/ctr.c lib/stream/rc4.c lib/stream/chacha.c lib/block/rijndael.c lib/block/rc6.c lib/block/twofish.c lib/block/anubis.c lib/block/seed.c lib/block/noekeon.c lib/hash.c lib/hash/sha2_256.c lib/hash/sha2_512.c lib/memwipe.c lib/random.c lib/pkcs7.c lib/block.c lib/stream.c
OBJ = version.o mac.o hmac.o mode.o threefish.o ctr.o rc4.o chacha.o rijndael.o rc6.o twofish.o anubis.o seed.o noekeon.o hash.o sha2_256.o sha2_512.o memwipe.o random.o pkcs7.o block.o stream.o

kripto: $(SRC)
	$(CC) $(CFLAGS) $(OPTIM) $(SRC)
	$(AR) rcs libkripto.a $(OBJ)
	$(CC) -shared $(LDFLAGS) -Wl,-soname,libkripto.so.0 -o libkripto.so.0.1.0 $(OBJ) -lc
	$(STRIP) -s libkripto.a libkripto.so.0.1.0

debug: $(SRC)
	$(CC) $(CFLAGS) -g -Werror -fstack-protector-all $(SRC)
	$(AR) rcs libkripto.a $(OBJ)
	$(CC) -shared $(LDFLAGS) -Wl,-soname,libkripto.so.0 -o libkripto.so.0.1.0 $(OBJ) -lc

clean:
	rm -f *.o *.a *.so

rebuild: clean build
