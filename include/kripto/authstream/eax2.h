#ifndef KRIPTO_AUTHSTREAM_EAX2_H
#define KRIPTO_AUTHSTREAM_EAX2_H

#include <kripto/stream.h>
#include <kripto/mac.h>

#include <kripto/authstream.h>

extern kripto_authstream_desc *kripto_authstream_eax2
(
	const kripto_stream_desc *stream,
	const kripto_mac_desc *mac
);

#endif
