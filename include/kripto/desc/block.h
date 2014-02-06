#ifndef KRIPTO_BLOCK_DESC_H
#define KRIPTO_BLOCK_DESC_H

struct kripto_block_desc
{
	kripto_block *(*create)
	(
		unsigned int,
		const void *,
		unsigned int
	);

	kripto_block *(*recreate)
	(
		kripto_block *,
		unsigned int,
		const void *,
		unsigned int
	);

	void (*tweak)
	(
		kripto_block *,
		const void *,
		unsigned int
	);

	void (*encrypt)(const kripto_block *, const void *, void *);

	void (*decrypt)(const kripto_block *, const void *, void *);

	void (*destroy)(kripto_block *);

	unsigned int blocksize;
	unsigned int maxkey;
};

#endif
