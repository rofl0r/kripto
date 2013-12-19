/*
 * Written in 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated
 * all copyright and related and neighboring rights to this software
 * to the public domain worldwide.
 * 
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef KRIPTO_ROTATE_H
#define KRIPTO_ROTATE_H

#include <stdint.h>

static inline uint8_t ROL8(uint8_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 7;
	return (x << r) | (x >> (8 - r));

#endif
}

static inline uint8_t ROR8(uint8_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rorb %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 7;
	return (x >> r) | (x << (8 - r));

#endif
}

static inline uint16_t ROL16(uint16_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 15;
	return (x << r) | (x >> (16 - r));

#endif
}

static inline uint16_t ROR16(uint16_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rorw %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 15;
	return (x >> r) | (x << (16 - r));

#endif
}

static inline uint32_t ROL32(uint32_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 31;
	return (x << r) | (x >> (32 - r));

#endif
}

static inline uint32_t ROR32(uint32_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rorl %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 31;
	return (x >> r) | (x << (32 - r));

#endif
}

static inline uint64_t ROL64(uint64_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 63;
	return (x << r) | (x >> (64 - r));

#endif
}

static inline uint64_t ROR64(uint64_t x, unsigned int r)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rorq %%cl, %0"
		: "=r" (x)
		: "0" (x), "c" (r)
	);
	return x;

#else

	r &= 63;
	return (x >> r) | (x << (64 - r));

#endif
}

static inline uint8_t ROL8_1(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $1, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 1) | (x >> 7);

#endif
}

static inline uint8_t ROL8_2(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $2, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 2) | (x >> 6);

#endif
}

static inline uint8_t ROL8_3(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $3, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 3) | (x >> 5);

#endif
}

static inline uint8_t ROL8_4(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $4, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 4) | (x >> 4);

#endif
}

static inline uint8_t ROL8_5(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $5, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 5) | (x >> 3);

#endif
}

static inline uint8_t ROL8_6(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $6, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 6) | (x >> 2);

#endif
}

static inline uint8_t ROL8_7(uint8_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolb $7, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 7) | (x >> 1);

#endif
}

#define ROR8_1 ROL8_7
#define ROR8_2 ROL8_6
#define ROR8_3 ROL8_5
#define ROR8_4 ROL8_4
#define ROR8_5 ROL8_3
#define ROR8_6 ROL8_3
#define ROR8_7 ROL8_1

static inline uint16_t ROL16_01(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $1, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 1) | (x >> 15);

#endif
}

static inline uint16_t ROL16_02(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $2, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 2) | (x >> 14);

#endif
}

static inline uint16_t ROL16_03(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $3, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 3) | (x >> 13);

#endif
}

static inline uint16_t ROL16_04(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $4, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 4) | (x >> 12);

#endif
}

static inline uint16_t ROL16_05(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $5, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 5) | (x >> 11);

#endif
}

static inline uint16_t ROL16_06(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $6, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 6) | (x >> 10);

#endif
}

static inline uint16_t ROL16_07(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $7, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 7) | (x >> 9);

#endif
}

static inline uint16_t ROL16_08(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $8, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 8) | (x >> 8);

#endif
}

static inline uint16_t ROL16_09(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $9, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 9) | (x >> 7);

#endif
}

static inline uint16_t ROL16_10(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $10, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 10) | (x >> 6);

#endif
}

static inline uint16_t ROL16_11(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $11, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 11) | (x >> 5);

#endif
}

static inline uint16_t ROL16_12(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $12, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 12) | (x >> 4);

#endif
}

static inline uint16_t ROL16_13(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $13, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 13) | (x >> 3);

#endif
}

static inline uint16_t ROL16_14(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $14, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 14) | (x >> 2);

#endif
}

static inline uint16_t ROL16_15(uint16_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"rolw $15, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 15) | (x >> 1);

#endif
}

#define ROR16_01 ROL16_15
#define ROR16_02 ROL16_14
#define ROR16_03 ROL16_13
#define ROR16_04 ROL16_12
#define ROR16_05 ROL16_11
#define ROR16_06 ROL16_10
#define ROR16_07 ROL16_09
#define ROR16_08 ROL16_08
#define ROR16_09 ROL16_07
#define ROR16_10 ROL16_06
#define ROR16_11 ROL16_05
#define ROR16_12 ROL16_04
#define ROR16_13 ROL16_03
#define ROR16_14 ROL16_02
#define ROR16_15 ROL16_01

static inline uint32_t ROL32_01(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $1, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 1) | (x >> 31);

#endif
}

static inline uint32_t ROL32_02(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $2, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 2) | (x >> 30);

#endif
}

static inline uint32_t ROL32_03(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $3, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 3) | (x >> 29);

#endif
}

static inline uint32_t ROL32_04(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $4, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 4) | (x >> 28);

#endif
}

static inline uint32_t ROL32_05(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $5, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 5) | (x >> 27);

#endif
}

static inline uint32_t ROL32_06(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $6, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 6) | (x >> 26);

#endif
}

static inline uint32_t ROL32_07(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $7, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 7) | (x >> 25);

#endif
}

static inline uint32_t ROL32_08(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $8, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 8) | (x >> 24);

#endif
}

static inline uint32_t ROL32_09(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $9, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 9) | (x >> 23);

#endif
}

static inline uint32_t ROL32_10(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $10, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 10) | (x >> 22);

#endif
}

static inline uint32_t ROL32_11(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $11, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 11) | (x >> 21);

#endif
}

static inline uint32_t ROL32_12(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $12, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 12) | (x >> 20);

#endif
}

static inline uint32_t ROL32_13(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $13, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 13) | (x >> 19);

#endif
}

static inline uint32_t ROL32_14(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $14, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 14) | (x >> 18);

#endif
}

static inline uint32_t ROL32_15(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $15, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 15) | (x >> 17);

#endif
}

static inline uint32_t ROL32_16(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $16, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 16) | (x >> 16);

#endif
}

static inline uint32_t ROL32_17(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $17, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 17) | (x >> 15);

#endif
}

static inline uint32_t ROL32_18(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $18, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 18) | (x >> 14);

#endif
}

static inline uint32_t ROL32_19(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $19, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 19) | (x >> 13);

#endif
}

static inline uint32_t ROL32_20(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $20, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 20) | (x >> 12);

#endif
}

static inline uint32_t ROL32_21(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $21, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 21) | (x >> 11);

#endif
}

static inline uint32_t ROL32_22(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $22, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 22) | (x >> 10);

#endif
}

static inline uint32_t ROL32_23(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $23, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 23) | (x >> 9);

#endif
}

static inline uint32_t ROL32_24(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $24, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 24) | (x >> 8);

#endif
}

static inline uint32_t ROL32_25(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $25, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 25) | (x >> 7);

#endif
}

static inline uint32_t ROL32_26(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $26, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 26) | (x >> 6);

#endif
}

static inline uint32_t ROL32_27(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $27, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 27) | (x >> 5);

#endif
}

static inline uint32_t ROL32_28(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $28, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 28) | (x >> 4);

#endif
}

static inline uint32_t ROL32_29(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $29, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 29) | (x >> 3);

#endif
}

static inline uint32_t ROL32_30(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $30, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 30) | (x >> 2);

#endif
}

static inline uint32_t ROL32_31(uint32_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& (defined(__i386__) || defined(__x86_64__))

	__asm__
	(
		"roll $31, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 31) | (x >> 1);

#endif
}

#define ROR32_01 ROL32_31
#define ROR32_02 ROL32_30
#define ROR32_03 ROL32_29
#define ROR32_04 ROL32_28
#define ROR32_05 ROL32_27
#define ROR32_06 ROL32_26
#define ROR32_07 ROL32_25
#define ROR32_08 ROL32_24
#define ROR32_09 ROL32_23
#define ROR32_10 ROL32_22
#define ROR32_11 ROL32_21
#define ROR32_12 ROL32_20
#define ROR32_13 ROL32_19
#define ROR32_14 ROL32_18
#define ROR32_15 ROL32_17
#define ROR32_16 ROL32_16
#define ROR32_17 ROL32_15
#define ROR32_18 ROL32_14
#define ROR32_19 ROL32_13
#define ROR32_20 ROL32_12
#define ROR32_21 ROL32_11
#define ROR32_22 ROL32_10
#define ROR32_23 ROL32_09
#define ROR32_24 ROL32_08
#define ROR32_25 ROL32_07
#define ROR32_26 ROL32_06
#define ROR32_27 ROL32_05
#define ROR32_28 ROL32_04
#define ROR32_29 ROL32_03
#define ROR32_30 ROL32_02
#define ROR32_31 ROL32_01

static inline uint64_t ROL64_01(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $1, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 1) | (x >> 63);

#endif
}

static inline uint64_t ROL64_02(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $2, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 2) | (x >> 62);

#endif
}

static inline uint64_t ROL64_03(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $3, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 3) | (x >> 61);

#endif
}

static inline uint64_t ROL64_04(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $4, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 4) | (x >> 60);

#endif
}

static inline uint64_t ROL64_05(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $5, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 5) | (x >> 59);

#endif
}

static inline uint64_t ROL64_06(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $6, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 6) | (x >> 58);

#endif
}

static inline uint64_t ROL64_07(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $7, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 7) | (x >> 57);

#endif
}

static inline uint64_t ROL64_08(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $8, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 8) | (x >> 56);

#endif
}

static inline uint64_t ROL64_09(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $9, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 9) | (x >> 55);

#endif
}

static inline uint64_t ROL64_10(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $10, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 10) | (x >> 54);

#endif
}

static inline uint64_t ROL64_11(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $11, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 11) | (x >> 53);

#endif
}

static inline uint64_t ROL64_12(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $12, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 12) | (x >> 52);

#endif
}

static inline uint64_t ROL64_13(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $13, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 13) | (x >> 51);

#endif
}

static inline uint64_t ROL64_14(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $14, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 14) | (x >> 50);

#endif
}

static inline uint64_t ROL64_15(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $15, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 15) | (x >> 49);

#endif
}

static inline uint64_t ROL64_16(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $16, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 16) | (x >> 48);

#endif
}

static inline uint64_t ROL64_17(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $17, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 17) | (x >> 47);

#endif
}

static inline uint64_t ROL64_18(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $18, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 18) | (x >> 46);

#endif
}

static inline uint64_t ROL64_19(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $19, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 19) | (x >> 45);

#endif
}

static inline uint64_t ROL64_20(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $20, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 20) | (x >> 44);

#endif
}

static inline uint64_t ROL64_21(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $21, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 21) | (x >> 43);

#endif
}

static inline uint64_t ROL64_22(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $22, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 22) | (x >> 42);

#endif
}

static inline uint64_t ROL64_23(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $23, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 23) | (x >> 41);

#endif
}

static inline uint64_t ROL64_24(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $24, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 24) | (x >> 40);

#endif
}

static inline uint64_t ROL64_25(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $25, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 25) | (x >> 39);

#endif
}

static inline uint64_t ROL64_26(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $26, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 26) | (x >> 38);

#endif
}

static inline uint64_t ROL64_27(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $27, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 27) | (x >> 37);

#endif
}

static inline uint64_t ROL64_28(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $28, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 28) | (x >> 36);

#endif
}

static inline uint64_t ROL64_29(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $29, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 29) | (x >> 35);

#endif
}

static inline uint64_t ROL64_30(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $30, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 30) | (x >> 34);

#endif
}

static inline uint64_t ROL64_31(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $31, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 31) | (x >> 33);

#endif
}

static inline uint64_t ROL64_32(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $32, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 32) | (x >> 32);

#endif
}

static inline uint64_t ROL64_33(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $33, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 33) | (x >> 31);

#endif
}

static inline uint64_t ROL64_34(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $34, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 34) | (x >> 30);

#endif
}

static inline uint64_t ROL64_35(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $35, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 35) | (x >> 29);

#endif
}

static inline uint64_t ROL64_36(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $36, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 36) | (x >> 28);

#endif
}

static inline uint64_t ROL64_37(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $37, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 37) | (x >> 27);

#endif
}

static inline uint64_t ROL64_38(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $38, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 38) | (x >> 26);

#endif
}

static inline uint64_t ROL64_39(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $39, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 39) | (x >> 25);

#endif
}

static inline uint64_t ROL64_40(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $40, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 40) | (x >> 24);

#endif
}

static inline uint64_t ROL64_41(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $41, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 41) | (x >> 23);

#endif
}

static inline uint64_t ROL64_42(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $42, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 42) | (x >> 22);

#endif
}

static inline uint64_t ROL64_43(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $43, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 43) | (x >> 21);

#endif
}

static inline uint64_t ROL64_44(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $44, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 44) | (x >> 20);

#endif
}

static inline uint64_t ROL64_45(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $45, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 45) | (x >> 19);

#endif
}

static inline uint64_t ROL64_46(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $46, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 46) | (x >> 18);

#endif
}

static inline uint64_t ROL64_47(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $47, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 47) | (x >> 17);

#endif
}

static inline uint64_t ROL64_48(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $48, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 48) | (x >> 16);

#endif
}

static inline uint64_t ROL64_49(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $49, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 49) | (x >> 15);

#endif
}

static inline uint64_t ROL64_50(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $50, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 50) | (x >> 14);

#endif
}

static inline uint64_t ROL64_51(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $51, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 51) | (x >> 13);

#endif
}

static inline uint64_t ROL64_52(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $52, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 52) | (x >> 12);

#endif
}

static inline uint64_t ROL64_53(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $53, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 53) | (x >> 11);

#endif
}

static inline uint64_t ROL64_54(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $54, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 54) | (x >> 10);

#endif
}

static inline uint64_t ROL64_55(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $55, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 55) | (x >> 9);

#endif
}

static inline uint64_t ROL64_56(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $56, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 56) | (x >> 8);

#endif
}

static inline uint64_t ROL64_57(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $57, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 57) | (x >> 7);

#endif
}

static inline uint64_t ROL64_58(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $58, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 58) | (x >> 6);

#endif
}

static inline uint64_t ROL64_59(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $59, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 59) | (x >> 5);

#endif
}

static inline uint64_t ROL64_60(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $60, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 60) | (x >> 4);

#endif
}

static inline uint64_t ROL64_61(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $61, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 61) | (x >> 3);

#endif
}

static inline uint64_t ROL64_62(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $62, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 62) | (x >> 2);

#endif
}

static inline uint64_t ROL64_63(uint64_t x)
{
#if (defined(__GNUC__) || defined(__clang__)) \
&& defined(__x86_64__)

	__asm__
	(
		"rolq $63, %0"
		: "=r" (x)
		: "0" (x)
	);
	return x;

#else

	return (x << 63) | (x >> 1);

#endif
}

#define ROR64_01 ROL64_63
#define ROR64_02 ROL64_62
#define ROR64_03 ROL64_61
#define ROR64_04 ROL64_60
#define ROR64_05 ROL64_59
#define ROR64_06 ROL64_58
#define ROR64_07 ROL64_57
#define ROR64_08 ROL64_56
#define ROR64_09 ROL64_55
#define ROR64_10 ROL64_54
#define ROR64_11 ROL64_53
#define ROR64_12 ROL64_52
#define ROR64_13 ROL64_51
#define ROR64_14 ROL64_50
#define ROR64_15 ROL64_49
#define ROR64_16 ROL64_48
#define ROR64_17 ROL64_47
#define ROR64_18 ROL64_46
#define ROR64_19 ROL64_45
#define ROR64_20 ROL64_44
#define ROR64_21 ROL64_43
#define ROR64_22 ROL64_42
#define ROR64_23 ROL64_41
#define ROR64_24 ROL64_40
#define ROR64_25 ROL64_39
#define ROR64_26 ROL64_38
#define ROR64_27 ROL64_37
#define ROR64_28 ROL64_36
#define ROR64_29 ROL64_35
#define ROR64_30 ROL64_34
#define ROR64_31 ROL64_33
#define ROR64_32 ROL64_32
#define ROR64_33 ROL64_31
#define ROR64_34 ROL64_30
#define ROR64_35 ROL64_29
#define ROR64_36 ROL64_28
#define ROR64_37 ROL64_27
#define ROR64_38 ROL64_26
#define ROR64_39 ROL64_25
#define ROR64_40 ROL64_24
#define ROR64_41 ROL64_23
#define ROR64_42 ROL64_22
#define ROR64_43 ROL64_21
#define ROR64_44 ROL64_20
#define ROR64_45 ROL64_19
#define ROR64_46 ROL64_18
#define ROR64_47 ROL64_17
#define ROR64_48 ROL64_16
#define ROR64_49 ROL64_15
#define ROR64_50 ROL64_14
#define ROR64_51 ROL64_13
#define ROR64_52 ROL64_12
#define ROR64_53 ROL64_11
#define ROR64_54 ROL64_10
#define ROR64_55 ROL64_09
#define ROR64_56 ROL64_08
#define ROR64_57 ROL64_07
#define ROR64_58 ROL64_06
#define ROR64_59 ROL64_05
#define ROR64_60 ROL64_04
#define ROR64_61 ROL64_03
#define ROR64_62 ROL64_02
#define ROR64_63 ROL64_01

#endif
