// SPDX-License-Identifier: MIT

#include "net_base.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>

namespace securepath::network {

net_base::net_base()
: work_guard_(work_io_context_.get_executor())
, signals_(io_context_, SIGINT, SIGTERM)
{
	signals_.async_wait(
		[this](std::error_code ec, int) {
			if(!ec) {
				LOG_TRACE("received signal, closing...");
				close();
			}
		});
}

net_base::~net_base() {
	try {
		signals_.cancel();
		work_guard_.reset();
		for(auto&& t : threads_) {
			if(t.joinable()) {
				t.join();
			}
		}
		for(auto& t : work_threads_) {
			if(t.joinable()) {
				t.join();
			}
		}
	} catch(...) {}
}

void net_base::close() {
	signals_.cancel();
	work_guard_.reset();
}

int net_base::run(int net_threads, int work_threads) {
	int ret = 1;
	LOG_INFO("starting net with {} threads and {} worker threads", net_threads, work_threads);
	if(init()) {
		for(int i = 0; i != net_threads; ++i) {
			threads_.emplace_back(
				[this]{
					io_context_.run();
				});
		}
		for(int i = 0; i != work_threads; ++i) {
			work_threads_.emplace_back(
				[this]{
					work_io_context_.run();
				});
		}
		ret = 0;
	} else {
		LOG_WARN("Network initialisation failed");
	}
	return ret;
}

void net_base::wait() {
	for(auto&& t : threads_) {
		t.join();
	}
	work_guard_.reset();
	for(auto&& t : work_threads_) {
		t.join();
	}
}

int net_base::run_and_wait(int net_threads, int work_threads) {
	int ret = run(net_threads, work_threads);
	wait();
	return ret;
}

asio::io_context& net_base::io_context() {
	return io_context_;
}

asio::io_context& net_base::work_io_context() {
	return work_io_context_;
}

bool net_base::init() {
	return true;
}

}
