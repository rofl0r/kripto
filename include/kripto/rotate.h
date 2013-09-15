#ifndef KRIPTO_ROTATE_H
#define KRIPTO_ROTATE_H

#define ROL(B, X, R) (((X) << (R)) | ((X) >> ((B) - (R))))
#define ROR(B, X, R) (((X) >> (R)) | ((X) << ((B) - (R))))

#define ROL8(X, R) ROL(8, X, R)
#define ROR8(X, R) ROR(8, X, R)

#define ROL16(X, R) ROL(16, X, R)
#define ROR16(X, R) ROR(16, X, R)

#define ROL32(X, R) ROL(32, X, R)
#define ROR32(X, R) ROR(32, X, R)

#define ROL64(X, R) ROL(64, X, R)
#define ROR64(X, R) ROR(64, X, R)

#endif
