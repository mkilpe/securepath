// SPDX-License-Identifier: MIT

#include "server_lib/key_server.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>

#include <exception>
#include <iostream>

namespace securepath {
namespace {

struct parameters : command_parser, key_server::server_params {
	bool help{};
	int timeout_arg{};

	parameters() {
		add(help, "help", "h", "show help");
		add(port, "port", "p", "listening port");
		add(root_public_key_file, "root", "", "DER file of the root public key anchoring certificate chains");
		add(timeout_arg, "timeout", "", "Connecting/Handshake timeout in seconds");
	}

	void handle_inputs() {
		if(timeout_arg) {
			timeout = std::chrono::seconds(timeout_arg);
		}
	}
};

}
}

int main(int argc, char* args[]) {
	int ret = 0;
	try {
		securepath::parameters p;
		p.parse(argc, args);
		if(p.help) {
			p.print_help(std::cout);
		} else {
			p.handle_inputs();
			securepath::key_server::server server(p);
			ret = server.run_and_wait();
		}
	} catch(std::exception const& ex) {
		LOG_WARN("Error: {}", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
		ret = 1;
	}
	return ret;
}
