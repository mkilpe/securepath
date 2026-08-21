// SPDX-License-Identifier: MIT

#include "util.hpp"
#include <securepath/log/detail/util.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <iostream>
#include <stdexcept>

namespace securepath::log::test {

TEST_CASE("log add file, line and level to buffer", "[util][log]") {

	char buffer[11] = {"          "};

	log_info info1{"file", 12, 0};
	log_info info2{"file", 123, 0};
	
	add_log_info_to_buffer(buffer, 0, 9, info1);

	CHECK(std::string(buffer) == "file:12  0");

	add_log_info_to_buffer(buffer, 0, 9, info2);

	CHECK(std::string(buffer) == "file:123 0");

}

TEST_CASE("log no space", "[util][log]") {

	char buffer[16] = {"               "};
	log_info info{"longlonglongfile", 123, 0};
	
	add_log_info_to_buffer(buffer, 1, 14, info);
	CHECK(std::string(buffer) == " ...gfile:123 0");

}

TEST_CASE("log level", "[util][log]") {

	char buffer[11] = {"          "};
	
	log_info info1{"file", 12, 1};
	log_info info2{"file", 12, 12};
	
	add_log_info_to_buffer(buffer, 0, 9, info1);
	CHECK(std::string(buffer) == "file:12  1");

	add_log_info_to_buffer(buffer, 0, 9, info2);
	CHECK(std::string(buffer) == "file:12 12");

}

TEST_CASE("log log_info space limit", "[util][log]") {

	char buffer1[17] = {"|              |"};
	char buffer2[17] = {"|              |"};
	char buffer3[17] = {"|              |"};
	char buffer4[17] = {"|              |"};
	char buffer5[17] = {"|              |"};
	char buffer6[17] = {"|              |"};
	
	log_info info1{"abcdefgh", 12, 1};  	// |abcdefgh:12  1|
	log_info info2{"abcdefghi", 12, 1}; 	// |abcdefghi:12 1|
	log_info info3{"abcdefghij", 12, 1}; 	// |...efghij:12 1|
	log_info info4{"abcdefghijk", 12, 1}; 	// |...fghijk:12 1|
	log_info info5{"abcdefghijkl", 12, 1}; 	// |...ghijkl:12 1|
	log_info info6{"abcdefghijklm", 12, 1}; // |...hijklm:12 1|

	add_log_info_to_buffer(buffer1, 1, 14, info1);
	add_log_info_to_buffer(buffer2, 1, 14, info2);
	add_log_info_to_buffer(buffer3, 1, 14, info3);
	add_log_info_to_buffer(buffer4, 1, 14, info4);
	add_log_info_to_buffer(buffer5, 1, 14, info5);
	add_log_info_to_buffer(buffer6, 1, 14, info6);
	
	CHECK(std::string(buffer1) == "|abcdefgh:12  1|");
	CHECK(std::string(buffer2) == "|abcdefghi:12 1|");
	CHECK(std::string(buffer3) == "|...efghij:12 1|");
	CHECK(std::string(buffer4) == "|...fghijk:12 1|");
	CHECK(std::string(buffer5) == "|...ghijkl:12 1|");
	CHECK(std::string(buffer6) == "|...hijklm:12 1|");

}


void check_and_clear(std::ostringstream& os, std::string s) {

	CHECK(os.str() == s);
	os.clear();
	os.str("");

}

struct tester_123 {
	std::string to_string() const {
		return "tester";
	}
};
}

template <>
struct std::formatter<securepath::log::test::tester_123> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }
    auto format(const securepath::log::test::tester_123& t, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{}", t.to_string());
    }
};

namespace securepath::log::test {

TEST_CASE("log print", "[util][log]") {

	std::ostringstream os;
	
	std::print(os, "");
	check_and_clear(os, "");

	std::print(os, "", 1, 1.1);
	check_and_clear(os, "");

	std::print(os, "message");
	check_and_clear(os, "message");

	std::string s = "a";
	std::print(os, "a {} b {} cc{}{}", s, 2, 1.2, true);
	check_and_clear(os, "a a b 2 cc1.2true");

	std::invalid_argument e("error msg");
	std::print(os, "error: {}", e.what());
	check_and_clear(os, "error: error msg");

	std::print(os, "message", 1, 2, 3, 4, "msg", false);
	check_and_clear(os, "message");

	tester_123 t;
	std::print(os, "{}", t);
	check_and_clear(os, t.to_string());

}

}
