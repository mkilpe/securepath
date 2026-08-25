// SPDX-License-Identifier: MIT

#include "framing.hpp"
#include "../types.hpp"

namespace securepath::crypto::detail {

octet_vector frame_message(std::string_view context, octet_span message) {
	if(context.size() > 255) {
		throw invalid_context("signature context longer than 255 octets");
	}
	static constexpr std::string_view prefix = "SPSIG";
	octet_vector framed;
	framed.reserve(prefix.size() + 1 + context.size() + message.size());
	framed.insert(framed.end(), prefix.begin(), prefix.end());
	framed.push_back(static_cast<std::uint8_t>(context.size()));
	framed.insert(framed.end(), context.begin(), context.end());
	framed.insert(framed.end(), message.begin(), message.end());
	return framed;
}

}
