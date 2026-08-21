// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/error.hpp>

#include <stdexcept>
#include <string>

namespace securepath::test {

TEST_CASE("error what() contains both code message and custom message", "[error]") {
	error e{make_error_code(errc::invalid_data), "tempo field missing"};
	std::string what = e.what();
	CHECK(what.find("invalid data") != std::string::npos);
	CHECK(what.find("tempo field missing") != std::string::npos);
}

TEST_CASE("error what() without custom message is the code message", "[error]") {
	error e{make_error_code(errc::timeout)};
	CHECK(std::string(e.what()) == "operation timed out");
}

TEST_CASE("error from exception_ptr preserves the original message", "[error]") {
	std::exception_ptr ep;
	try {
		throw std::runtime_error("disk on fire");
	} catch(...) {
		ep = std::current_exception();
	}

	error e{ep};
	std::string what = e.what();
	CHECK(!what.empty());
	CHECK(what.find("disk on fire") != std::string::npos);
	CHECK(e.message() == "disk on fire");
}

}
