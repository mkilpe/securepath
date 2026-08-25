// SPDX-License-Identifier: MIT

#include <securepath/infrastructure/packet_transport/server/server_lib/packet_server.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>

#include <iostream>

namespace securepath {

struct parameters : command_parser, packet_transport::packet_server_params {
	int timeout_arg{};

	parameters() {
		add(timeout_arg, "timeout", "", "Connecting/Handshake timeout in seconds");
	}

	void handle_inputs() {
		if(timeout_arg) {
			timeout = std::chrono::seconds(timeout_arg);
		}
	}
};

}

int main(int argc, char* args[]) {
	int ret = 0;
	try {
		securepath::log::backend::add_backend<securepath::log::backend::file_output>("file", "packet_server.log");
		securepath::parameters p;
		p.parse(argc, args);
		p.handle_inputs();

		securepath::packet_transport::packet_server server(p);
		ret = server.run_and_wait();

	} catch(std::exception const& ex) {
		LOG_WARN("Error: {}", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
		ret = 1;
	}
	return ret;
}
