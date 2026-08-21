// SPDX-License-Identifier: MIT

#include "util.hpp"

#include <string>
#include <iostream>

namespace securepath::log {

bool gmtime(std::time_t time, std::tm& out) {
	return
#if defined(WIN32) or defined(__MINGW32__)
	::gmtime_s(&out, &time) == 0;
#else
	::gmtime_r(&time, &out) != nullptr;
#endif
}

std::time_t timegm(std::tm& in) {
	return
#if defined(WIN32) or defined(__MINGW32__)
	::_mkgmtime(&in);
#else
	::timegm(&in);
#endif
}

namespace {

int ten_to_pow(int x) {
	int res = 1;
	while(x > 0) {
		res *= 10;
		x--;
	}
	return res;
}

void add_line_number_to_buffer(char* buffer, int line, int length, int first_index, int last_index) {

	buffer[first_index++] = ':';
	int x = ten_to_pow(length);

	while(x > 9 && first_index <= last_index) {
		buffer[first_index++] = (line % x) / (x/10) + '0';
		x /= 10;
	}

}

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

void add_dots_to_beginning(char* buffer, int& first_index) {
	buffer[first_index++] = '.';
	buffer[first_index++] = '.';
	buffer[first_index++] = '.';
}

void fix_beginning_of_file_name(char* buffer, int& first_index, int& name_start, int space) {

	add_dots_to_beginning(buffer, first_index);
	name_start = name_start + 3;

	while(space < 0) {
		name_start++;
		space++;
	}
}

void add_file_to_buffer(char* buffer, char const* file, int& first_index, int& last_index, int& name_start, int& name_end, int& reserve) {

	for(int i = name_start; first_index + reserve <= last_index && i < name_end; ++i) {
		buffer[first_index] = file[i];
		++first_index;
	}

}

void add_log_level_to_end(char* buffer, int& last_index, int level) {

	if(level == 0) {
		buffer[last_index--] = '0';
	}

	while(level > 0) {
		buffer[last_index--] = level % 10 + '0';
		level /= 10;
	}

}

int get_line_number_length(int line) {

	int res = 1;
	line /= 10;
	while(line > 0) {
		res++;
		line /= 10;
	}
	return res;

}

}

void add_log_info_to_buffer(char* buffer, int first_index, int last_index, log_info const& info) {

	buffer[first_index] = ' ';

	add_log_level_to_end(buffer, last_index, info.level);

	int line_length = get_line_number_length(info.line);
	int reserve = line_length + 1;
	int name_start = 0;
	int name_end = -1;

	find_file_name_end_points(info.file, name_start, name_end);

	int space = last_index - first_index + 1 - (name_end - name_start + 1 + reserve);

	if(space < 0) {
		fix_beginning_of_file_name(buffer, first_index, name_start, space);
	}

	add_file_to_buffer(buffer, info.file, first_index, last_index, name_start, name_end, reserve);
	add_line_number_to_buffer(buffer, info.line, line_length, first_index, last_index);
}

}