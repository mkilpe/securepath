// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/log/detail/util.hpp>
#include <securepath/util/print_util.hpp>

#include <chrono>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace securepath::log::test {

#define LOG_TEST_1(logger, ...) ::securepath::log::log_handler(::securepath::log::log_info{__FILE__, __LINE__, 0}, logger, __VA_ARGS__);

constexpr std::string test_string1 = "test1";
constexpr std::string test_string2 = "test2";
constexpr std::string test_string3 = "test3";
constexpr std::string test_string4 = "test4";
constexpr std::string test_string5 = "test5";

const std::string log_file1 = "log_file_aaa.log";
const std::string log_file2 = "log_file_bbb.log";
const std::string log_file3 = "log_file_ccc.log";

const std::string log_name1 = "name1";
const std::string log_name2 = "name2";
const std::string log_name3 = "name3";

inline
int ttt_add_line_to_buffer(char buffer[], int first_index, int last_index, log_info const& info) {
	
	std::string line = std::to_string(info.line);

	for(int i = (int)line.size() - 1; i >= 0 && last_index >= first_index; --i) {
		buffer[last_index] = line[i];
		--last_index;
	}

	if(first_index <= last_index) {
		buffer[last_index] = ':';
	}

	return --last_index;
}

inline 
void iii_add_line(char buffer[], int first_index, int last_index, std::string const& line) {

	buffer[first_index++] = ':';

	for(int i = 0; i < (int)line.size() && first_index <= last_index; ++i) {
		buffer[first_index] = line[i];
		++first_index;
	}

}

inline 
int iii_add_file_to_buffer(char* buffer, char const* file, int first_index, int last_index) {
	return 0;
}

inline
void find_file_name_end_points(char const* file, int& name_start, int& name_end) {

	bool done = false;

	for(int i = 0; !done; ++i) {
		if(file[i] == '\\' || file[i] == '/') {
			name_start = i + 1;
		} else if(file[i] == '\0') {
			name_end = i;
			done = true;
		}
	}
}

inline
void add_dots_to_beginning(char* buffer, int& first_index) {
	buffer[first_index] = '.';
	buffer[++first_index] = '.';
	buffer[++first_index] = '.';
}

inline
void fix_beginning_of_file_name(char* buffer, int& first_index, int& name_start, int l) {

	add_dots_to_beginning(buffer, first_index);
	name_start = name_start + 3;
	l = l + 3;

	while(l < 0) {
		first_index++;
		name_start++;
		l++;
	}
}

inline
void ttt_add_file_and_line(char buffer[], int first_index, int last_index, log_info const& info) {

	buffer[first_index] = ' ';

	std::string line = std::to_string(info.line);
	int reserve = (int)line.size() + 1;
	int name_start = 0;
	int name_end = -1;
	
	find_file_name_end_points(info.file, name_start, name_end);
	
	int space = last_index - first_index + 1 - (name_end - name_start + 1 + reserve);

	if(space < 0) {
		fix_beginning_of_file_name(buffer, first_index, name_start, space);
	}
	
	for(int i = name_start; first_index + reserve <= last_index && i < name_end; ++i) {
		buffer[first_index] = info.file[i];
		++first_index;
	}

	
	iii_add_line(buffer, first_index, last_index, line);
	
}

template<typename... Args>	
void default_logger_test_impl(std::string& m, log_info const& info, char const* format, Args const&... args) {
	using time_point = std::chrono::time_point<std::chrono::system_clock>;
	char buffer[71] = {"                                                                      "};
	std::tm t{};
	auto time = time_point::clock::now();
	if(gmtime(time_point::clock::to_time_t(time), t)) {
		std::snprintf(buffer, 20, "%02u.%02u.%04u %02u:%02u:%02u"
			, static_cast<unsigned int>(t.tm_mday), static_cast<unsigned int>(t.tm_mon + 1)
			, static_cast<unsigned int>(t.tm_year + 1900), static_cast<unsigned int>(t.tm_hour)
			, static_cast<unsigned int>(t.tm_min), static_cast<unsigned int>(t.tm_sec));
		int ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count() % 1000;
		std::snprintf(buffer + 19, 6, ".%03u ", static_cast<unsigned int>(ms));
	}
	//ttt_add_file_and_line(buffer, 24, 69, info);
	m = buffer + std::format(format, args...);
}

struct test_logger_1 {
	using logger_type = std::ofstream;
	test_logger_1(std::string const& file)
	: out_(file, std::ios_base::app)
	{}
	
	template<typename... Args>
	void log(log_info const& info, char const* format, Args const&... args) {
		std::string s;
		default_logger_test_impl(s, info, format, args...);
		//formatted_message m{info, std::string_view{s}, std::string_view{}};
	 	//out_.write(m.message.data(), m.message.size());
		//out_ << std::endl;
	}

	int get_min_log_level() {
		return 0;
	}
private:
	std::ofstream out_;
};

struct test_output_1 : public backend::output_base {

	test_output_1(std::string const& file, int level)
	: out_(file, std::ios_base::app)
	, level_(level)
	{}

	virtual void log(formatted_message const& m) {
		if(level_ <= m.info.level) {
			out_.write(m.message.data(), m.message.size());
			out_ << std::endl;
		}
	}

	virtual int get_min_log_level() const { 
		return level_;
	}
private:
	std::ofstream out_;
	int level_;
};

inline
std::string get_log_file_content(std::string const& file) {
	
	std::ifstream ifs(file);
	std::string line;
	std::stringstream stream;

	while(std::getline(ifs, line)) {
		stream << line << "\n";
	}
	return stream.str();
}

inline
bool file_contains_string(std::string const& file, std::string const& s) {
	
	std::string content = get_log_file_content(file);
	return content.find(s) != std::string::npos;
	
}

}

