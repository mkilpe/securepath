// SPDX-License-Identifier: MIT

#include "util.hpp"
#include <securepath/test_frame/test_suite.hpp>

namespace securepath::log::test {

TEST_CASE("log_simple_test", "[format][log]") {

	std::remove(log_file1.c_str());
	log::backend::add_backend<log::backend::file_output>(log_name1, log_file1);

	CHECK(!file_contains_string(log_file1, std::string("test")));

	LOG_TRACE("test");

	CHECK(file_contains_string(log_file1, std::string("test")));

	LOG_TRACE("test {}", 1);
	LOG_TRACE("test {} - {}", 2, 1.2);
	LOG_TRACE("{} test {}{}", 1, "t ", 2);
	LOG_TRACE("{}{}{}{}test", "-",1,"--",3);
	LOG_TRACE("{}test{}", true, false);
	LOG_TRACE("\\% some\\a \\% test{}\\% \\%", true);
	LOG_TRACE("{{}} braces {}", 42);

	std::string content = get_log_file_content(log_file1);

	CHECK(content.find("test 1") != std::string::npos);
	CHECK(content.find("test 2 - 1.2") != std::string::npos);
	CHECK(content.find("1 test t 2") != std::string::npos);
	CHECK(content.find("-1--3test") != std::string::npos);
	// std::format semantics: bools print as true/false, % is not special
	CHECK(content.find("truetestfalse") != std::string::npos);
	CHECK(content.find("\\% some\\a \\% testtrue\\% \\%") != std::string::npos);
	CHECK(content.find("{} braces 42") != std::string::npos);

	log::backend::remove(log_name1);
	std::remove(log_file1.c_str());

}

TEST_CASE("log contains file line date", "[format][log]") {
	
	std::remove(log_file2.c_str());

	test_logger_1 logger(log_file2);

	//LOG_TEST_1(logger, "hop1");
	//LOG_TEST_1(logger, "hop2");

	std::string content = get_log_file_content(log_file2);

	std::cout << content << std::endl;
	
	std::remove(log_file2.c_str());
}

}
