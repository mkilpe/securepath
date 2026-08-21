// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

namespace securepath::serialisation {

namespace asn_class {

enum {
	universal_c = 0x0,
	application_c = 0x1,
	context_specific_c = 0x2,
	private_c = 0x3
};

}

using asn_class_type = std::uint_fast8_t;

namespace asn_tag {

enum {
	boolean = 0x01,
	integer = 0x02,
	octet_string = 0x04,
	real = 0x09,
	sequence = 0x10,
	t61string = 0x14,
	generalised_time = 0x18
};

}

struct asn_header {
	asn_class_type asn_class{};
	std::uint64_t tag{};
	std::uint64_t length{};
	bool is_constructed{};
};

/// Limit maximum size of primitive asn elements (strings, integers...), whose
/// declared length is allocated up front, so that memory usage is limited in
/// case of malicious remote peer. The encoder refuses to write larger ones so
/// a document that saves is always loadable.
std::uint64_t const max_structure_size{1024*1024*2};

/// Constructed types (sequences) only set a parsing boundary — nothing is
/// allocated from their declared length — so they may grow with content;
/// without the higher limit a large document could be saved but never loaded
std::uint64_t const max_constructed_size{std::uint64_t(1024)*1024*512};

}

