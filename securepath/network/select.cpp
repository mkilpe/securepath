// SPDX-License-Identifier: MIT

#include "select.hpp"

#include <sys/select.h>

namespace securepath {

bool wait(socket_type& s, std::size_t milliseconds) {
	fd_set read_set{};
	FD_SET(s.native_handle(), &read_set);
	timeval tv{};
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	return ::select(s.native_handle() + 1, &read_set, nullptr, nullptr, &tv) == 1;
}

}
