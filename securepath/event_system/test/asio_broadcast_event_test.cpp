// SPDX-License-Identifier: MIT

// asio_broadcast_observer specifics: delivery and disconnect through an
// io_context running on another thread, and observer destruction while a
// handler may be in flight. Generic broadcast semantics are covered in
// broadcast_event_test.cpp.

#include "util.hpp"

#include <securepath/event_system/asio_broadcast_observer.hpp>
#include <securepath/event_system/broadcast_event_handler.hpp>
#include <securepath/event_system/broadcast_observer.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <asio.hpp>

#include <atomic>
#include <string>
#include <thread>

namespace securepath::event_system {
namespace test {
namespace {

struct test_event {
	using type = void(std::string);
};

struct simple_event {
	using type = void();
};

struct event_context {
	event_context()
	: signals(context, SIGINT, SIGTERM)
	{
		signals.async_wait( [](std::error_code, int) {} );
		thread = std::thread([&](){ context.run(); });
	}

	~event_context() {
		context.stop();
		thread.join();
	}

	asio::io_context context;
	asio::signal_set signals;
	std::thread thread;
};

}

TEST_CASE("asio_bc_simple_event", "[event_system]") {
	event_context ec;
	broadcast_event_handler handler;
	asio_broadcast_observer observer(handler, ec.context);

	std::atomic<bool> happened(false);
	observer.connect<test_event>( [&](std::string s) { CHECK(s == "test"); happened = true; } );

	handler.emit<test_event>("test");

	wait_for_event(500, happened);
	CHECK(happened);
}

TEST_CASE("asio_bc_observer_disconnect", "[event_system]") {
	event_context ec;
	broadcast_event_handler handler;
	asio_broadcast_observer observer(handler, ec.context);

	std::atomic<bool> happened(false);
	observer.connect<test_event>( [&](std::string s) { happened = true; } );
	observer.disconnect(typeid(test_event));

	handler.emit<test_event>("test");

	wait_for_event(500, happened);
	CHECK(!happened);
}

TEST_CASE("destruct_bc_observer", "[event_system]") {
	event_context ec;
	broadcast_event_handler h;
	std::atomic<int> counter(0);

	{
		asio_broadcast_observer o(h, ec.context);
		o.connect<simple_event>( [&]() { counter++; std::this_thread::sleep_for(500ms); } );
		h.emit<simple_event>();
		h.emit<simple_event>();
	}

	CHECK(counter < 2);
	wait_for_event(500, [&]{ return counter > 1; });
	CHECK(counter < 2);
}

}
}
