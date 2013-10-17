#ifndef KRIPTO_AUTHSTREAM_OBJECT_H
#define KRIPTO_AUTHSTREAM_OBJECT_H

#include <kripto/authstream.h>

struct kripto_authstream_object
{
	const kripto_authstream_desc *desc;
	unsigned int multof;
};

#endif
