#ifndef KRIPTO_AE_EAX2_H
#define KRIPTO_AE_EAX2_H

#include <kripto/stream.h>
#include <kripto/mac.h>

#include <kripto/ae.h>

extern kripto_ae_desc *kripto_ae_eax2
(
	const kripto_stream_desc *stream,
	const kripto_mac_desc *mac
);

#endif
