#ifndef KRIPTO_STREAM_OBJECT_H
#define KRIPTO_STREAM_OBJECT_H

#include <kripto/stream.h>

struct kripto_stream_object
{
	const kripto_stream_desc *desc;
	unsigned int multof;
};

#endif
