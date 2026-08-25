// SPDX-License-Identifier: MIT

#pragma once

#include <asio/io_context.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/signal_set.hpp>

#include <thread>
#include <vector>

namespace securepath::network {

/// Base class for network operations, creates two sets of io_contexts
class net_base {
public:
	net_base();
	virtual ~net_base();

	/// Start threads and return immediately
	virtual int run(int net_threads = 2, int work_threads = 2);

	/// Wait until close is called (or the threads return for some other reason)
	virtual void wait();

	/// Start threads and wait until close is called
	virtual int run_and_wait(int net_threads = 2, int work_threads = 2);
	virtual void close();

	asio::io_context& io_context();
	asio::io_context& work_io_context();

protected:
	virtual bool init();

protected:
	asio::io_context io_context_;
	asio::io_context work_io_context_;
	asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
	asio::signal_set signals_;
	std::vector<std::thread> threads_;
	std::vector<std::thread> work_threads_;
};

}
