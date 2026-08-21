// SPDX-License-Identifier: MIT

#include "backend.hpp"
#include "config.hpp"

#include <algorithm>
#include <atomic>
#include <vector>

namespace securepath::log::backend {

struct output_with_name {
	std::string name;
	output_ptr output;
};

class basic_backend {
public:
	void add(std::string name, output_ptr p) {
		lock_guard l(mutex_);
		outputs_.push_back( output_with_name{std::move(name), std::move(p)} );
		calc_min_log_level();
	}

	void remove(std::string const& name) {
		lock_guard l(mutex_);
		outputs_.erase(
			std::remove_if(outputs_.begin(), outputs_.end(),
				[&name](auto&& v){ return v.name == name;}), outputs_.end());
		calc_min_log_level();
	}

	void log(formatted_message const& m) {
		lock_guard l(mutex_);
		for(auto&& v : outputs_) {
			v.output->log(m);
		}
	}

	int get_min_log_level() const {
		return min_log_level_;
	}

	void calc_min_log_level() {
		int level = 100;
		for(auto&& v : outputs_) {
			level = std::min(level, v.output->get_min_log_level());
		}
		min_log_level_ = level;
	}
private:
	mutable mutex_type mutex_;
	std::vector<output_with_name> outputs_;
	std::atomic<int> min_log_level_{100};
};

namespace {
	basic_backend& get_backend() {
		static basic_backend b;
		return b;
	}
}

void add(std::string name, output_ptr p) {
	get_backend().add(std::move(name), std::move(p));
}

void remove(std::string const& name) {
	get_backend().remove(name);
}

void log(formatted_message const& m) {
	get_backend().log(m);
}

int get_min_log_level() {
	return get_backend().get_min_log_level();
}

}
