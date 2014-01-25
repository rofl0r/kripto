#ifndef KRIPTO_AE_OBJECT_H
#define KRIPTO_AE_OBJECT_H

#include <kripto/ae.h>

struct kripto_ae_object
{
	const kripto_ae_desc *desc;
	unsigned int multof;
};

#endif
