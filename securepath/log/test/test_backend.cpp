// SPDX-License-Identifier: MIT

#include "util.hpp"
#include <securepath/test_frame/test_suite.hpp>

namespace securepath::log::test {

TEST_CASE("log backend can be added and removed", "[backend][log]") {
	
	std::remove(log_file1.c_str());
	std::remove(log_file2.c_str());
	
	backend::add_backend<backend::file_output>(log_name1, log_file1);
	backend::add(log_name2, std::make_unique<backend::file_output>(log_file2));

	LOG_TRACE(test_string1.c_str());
	backend::remove(log_name1);
	LOG_TRACE(test_string2.c_str());
	backend::remove(log_name2);
	LOG_TRACE(test_string3.c_str());

	std::string res1 = get_log_file_content(log_file1);
	std::string res2 = get_log_file_content(log_file2);

	CHECK(res1.find(test_string1) != std::string::npos);
	CHECK(res1.find(test_string2) == std::string::npos);
	CHECK(res1.find(test_string3) == std::string::npos);
	
	CHECK(res2.find(test_string1) != std::string::npos);
	CHECK(res2.find(test_string2) != std::string::npos);
	CHECK(res2.find(test_string3) == std::string::npos);
	
	std::remove(log_file1.c_str());
	std::remove(log_file2.c_str());

}

TEST_CASE("log backend add remove multiple times during run", "[backend][log]") {
	
	std::remove(log_file1.c_str());
	
	backend::add_backend<backend::file_output>(log_name1, log_file1);
	backend::remove(log_name1);

	LOG_TRACE(test_string1.c_str());
	backend::add_backend<backend::file_output>(log_name1, log_file1);
	LOG_TRACE(test_string2.c_str());
	backend::remove(log_name1);
	LOG_TRACE(test_string3.c_str());
	backend::add_backend<backend::file_output>(log_name1, log_file1);
	LOG_TRACE(test_string4.c_str());
	backend::remove(log_name1);
	LOG_TRACE(test_string5.c_str());

	std::string res = get_log_file_content(log_file1);
	
	CHECK(res.find(test_string1) == std::string::npos);
	CHECK(res.find(test_string2) != std::string::npos);
	CHECK(res.find(test_string3) == std::string::npos);
	CHECK(res.find(test_string4) != std::string::npos);
	CHECK(res.find(test_string5) == std::string::npos);

	std::remove(log_file1.c_str());

}

TEST_CASE("log backend log function", "[backend][log]") {

	std::remove(log_file1.c_str());

	backend::add_backend<backend::file_output>(log_name1, log_file1);
	backend::log(formatted_message{log_info{}, std::string_view{test_string1}, std::string_view{}});
	
	std::string res = get_log_file_content(log_file1);
	CHECK(res.find(test_string1) != std::string::npos);

	backend::remove(log_name1);
	std::remove(log_file1.c_str());

}


TEST_CASE("log backend log level", "[backend][log]") {
	
	std::remove(log_file1.c_str());
	std::remove(log_file2.c_str());
	std::remove(log_file3.c_str());

	int level0 = 100;
	int level1 = 9;
	int level2 = 5;
	int level3 = 0;

	CHECK(backend::get_min_log_level() == level0);
	
	backend::add(log_name1, std::make_unique<test_output_1>(log_file1, level1));
	CHECK(backend::get_min_log_level() == level1);

	backend::add(log_name2, std::make_unique<test_output_1>(log_file2, level2));
	CHECK(backend::get_min_log_level() == level2);

	backend::add_backend<backend::file_output>(log_name3, log_file3);
	CHECK(backend::get_min_log_level() == level3);

	LOG_TRACE(test_string1.c_str());
	LOG_INFO(test_string2.c_str());
	LOG_WARN(test_string3.c_str());

	std::string res1 = get_log_file_content(log_file1);
	std::string res2 = get_log_file_content(log_file2);
	std::string res3 = get_log_file_content(log_file3);
	
	CHECK(res1.find(test_string1) == std::string::npos);
	CHECK(res1.find(test_string2) == std::string::npos);
	CHECK(res1.find(test_string3) == std::string::npos);

	CHECK(res2.find(test_string1) == std::string::npos);
	CHECK(res2.find(test_string2) == std::string::npos);
	CHECK(res2.find(test_string3) != std::string::npos);

	CHECK(res3.find(test_string1) != std::string::npos);
	CHECK(res3.find(test_string2) != std::string::npos);
	CHECK(res3.find(test_string3) != std::string::npos);

	backend::remove(log_name3);
	CHECK(backend::get_min_log_level() == level2);

	backend::remove(log_name2);
	CHECK(backend::get_min_log_level() == level1);

	backend::remove(log_name1);
	CHECK(backend::get_min_log_level() == level0);	

	std::remove(log_file1.c_str());
	std::remove(log_file2.c_str());
	std::remove(log_file3.c_str());

}

}
