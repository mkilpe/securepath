// SPDX-License-Identifier: MIT

#include "server_lib/key_server.hpp"

#include <securepath/log/log.hpp>

#include <exception>
#include <iostream>

int main() {
	int ret = 0;
	try {
		securepath::key_server::server server;
		ret = server.run_and_wait();
	} catch(std::exception const& ex) {
		LOG_WARN("Error: {}", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
		ret = 1;
	}
	return ret;
}
