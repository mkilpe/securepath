// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/debug_print.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>

#include <sstream>

namespace securepath::test {

TEST_CASE("debug print log", "[debug_print][.]") {
	
	std::string file = "test_util_41351351";
	std::remove(file.c_str());

	log::backend::add_backend<log::backend::file_output>("util_test_1", file);
	debug_print("msg {} ab{}", 1, 'c');
	log::backend::remove("util_test_1");

	std::ifstream ifs(file);
	std::string line;
	std::stringstream stream;

	while(std::getline(ifs, line)) {
		stream << line << "\n";
	}

	std::string res = stream.str();
	CHECK(res.find("msg 1 abc") != std::string::npos);

	std::remove(file.c_str());
}	

}
