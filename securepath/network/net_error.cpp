// SPDX-License-Identifier: MIT

#include "net_error.hpp"

#include <ostream>

namespace securepath::network {

std::ostream& operator<<(std::ostream& out, net_error const& err) {
	if(err) {
		out << err.code() << " (" << err.category() << "): " << err.message() << " (" << err.aux_message() << ")";
	} else {
		out << "no error";
	}
	return out;
}

}
