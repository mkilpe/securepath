// SPDX-License-Identifier: MIT

#pragma once

#include <asio/ip/udp.hpp>

#include <cstddef>

namespace securepath {

using socket_type = asio::ip::udp::socket;
bool wait(socket_type& s, std::size_t milliseconds);

}
