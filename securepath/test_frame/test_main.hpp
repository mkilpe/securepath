// SPDX-License-Identifier: MIT

#include <securepath/log/log.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/util/print_util.hpp>

#include <catch2/catch_session.hpp>

namespace securepath {

int run_tests(int argc, char* args[]) {
	std::vector<std::string_view> arguments{args, args+argc};
	log::backend::add_backend<log::backend::file_output>("file", "debug.log");
	LOG_INFO("Starting test: {}", print_list_to_string(arguments, " ", "\""));
	return Catch::Session().run(argc, args);
}

}
