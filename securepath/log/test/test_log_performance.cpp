// SPDX-License-Identifier: MIT

#include "util.hpp"

#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>

#include <securepath/log/log.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/timer.hpp>
#include <securepath/util/print_util.hpp>
#include <securepath/log/detail/util.hpp>
#include <securepath/test_frame/test_print.hpp>

#include <iostream>
#include <limits>

namespace securepath::log::test {

void test_log_format_speed_0args_short() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "static string, short one");
}

void test_log_format_speed_0args_long() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

void test_log_format_speed_1args_short() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "static % string, short one", 123456);
}

void test_log_format_speed_2args_short() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "static % string, % short one", 123456, "hipshopd");
}

void test_log_format_speed_3args_short() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "static % string, % short  % one", 123456, "hipshkdf", 1.345);
}

void test_log_format_speed_4args_short() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "static % string, % short  % on % e", 123456, "hipshkdf", 1.345, 12354);
}

void test_log_format_speed_5args_short() {
	default_log_impl([](auto...){}, log_info{"perftest", 123, 1}, "static % string, % short  % on % e", 123456, "hipshkdf", 1.345, 12354, "dhff");
}

template<typename Func>
void test_log_performance(Func func) {
	int rounds = 10000000;
	timer t;
	for(int i = 0; i != rounds; ++i) {
		func();
	}
	auto res = (t.current_time_point() - t.start_time_point()) / rounds;
	std::cout << "function invocation took on average: " << securepath::test::duration_to_string(res) << std::endl;
}

TEST_CASE("performance_test", "[performance][.]") {
	std::cout << "formatting with 0 arguments, short string:\n";
	test_log_performance(test_log_format_speed_0args_short);

	std::cout << "formatting with 0 arguments, long string:\n";
	test_log_performance(test_log_format_speed_0args_long);

	std::cout << "formatting with 1 arguments, short string:\n";
	test_log_performance(test_log_format_speed_1args_short);

	std::cout << "formatting with 2 arguments, short string:\n";
	test_log_performance(test_log_format_speed_2args_short);

	std::cout << "formatting with 3 arguments, short string:\n";
	test_log_performance(test_log_format_speed_3args_short);

	std::cout << "formatting with 4 arguments, short string:\n";
	test_log_performance(test_log_format_speed_4args_short);

	std::cout << "formatting with 5 arguments, short string:\n";
	test_log_performance(test_log_format_speed_5args_short);
}

}
