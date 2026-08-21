// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"
#include "span.hpp"

#include <string>

namespace securepath {

	/// creates hex encoded string from binary data, uses capital letters in the encoding
	std::string to_hex(octet_span);

	/// create binary data from hex encoded string, accepts small and capital letters in the encoding
	octet_vector from_hex(std::string_view);

}

