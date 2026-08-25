// SPDX-License-Identifier: MIT

#include "util.hpp"

#include <securepath/event_system/broadcast_event_handler.hpp>
#include <securepath/event_system/broadcast_observer.hpp>
#include <securepath/event_system/asio_broadcast_observer.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <asio.hpp>

#include <iostream>

namespace securepath::event_system {
namespace test {

struct test_event {
	using type = void(std::string);
};

struct test_event2 {
	using type = void(std::string);
};

struct simple_event {
	using type = void();
};

struct event_context {
	event_context()
	: signals(context, SIGINT, SIGTERM)
	{
		signals.async_wait(	[](std::error_code, int) {} );
		thread = std::thread([&](){ context.run(); }) ;
	}

	~event_context() {
		context.stop();
		thread.join();
	}

	asio::io_context context;
	asio::signal_set signals;
	std::thread thread;
};

/*
	asio::io_context context;
	asio::signal_set signals(context, SIGINT, SIGTERM);
	signals.async_wait(	[](std::error_code, int) {} );
	std::thread thread([&](){ context.run(); });
	...
	context.stop();
	thread.join();
*/

TEST_CASE("simple_bc_event_test", "[event_system]") {

	event_context ec;

	broadcast_event_handler handler;
	asio_broadcast_observer observer(handler, ec.context);

	std::atomic<bool> happened(false);

	CHECK(!happened);
	observer.connect<test_event>( [&](std::string s) {CHECK(s == "test"); happened = true; } );

	handler.emit<test_event>("test");

	wait_for_event(500, happened);
	CHECK(happened);

}

TEST_CASE("bc_observer_disconnect_test", "[event_system]") {

	event_context ec;
	broadcast_event_handler handler;
	asio_broadcast_observer observer(handler, ec.context);
	std::atomic<bool> happened(false);

	observer.connect<test_event>( [&](std::string s) {CHECK(s == "test"); happened = true; } );
	observer.disconnect(typeid(test_event));

	handler.emit<test_event>("test");

	wait_for_event(500, happened);
	CHECK(!happened);

}

TEST_CASE("bc_correct_event_call_test", "[event_system]") {

	event_context ec;

	broadcast_event_handler h;
	asio_broadcast_observer o(h, ec.context);

	std::atomic<bool> happened(false);
	std::atomic<bool> happened2(false);
	std::atomic<bool> happened3(false);

	o.connect<test_event>( [&](std::string s) {	happened = true; } );
	o.connect<test_event2>( [&](std::string s) { happened2 = true; } );
	o.connect<simple_event>( [&]() { happened3 = true; } );

	h.emit<test_event2>("test");
	wait_for_event(500, happened2);

	CHECK(!happened);
	CHECK(happened2);
	CHECK(!happened3);
}

TEST_CASE("multiple_bc_observers_for_event", "[event_system]") {

	event_context ec;
	broadcast_event_handler h;

	asio_broadcast_observer o1(h, ec.context);
	asio_broadcast_observer o2(h, ec.context);
	asio_broadcast_observer o3(h, ec.context);

	std::atomic<bool> happened_o1(false);
	std::atomic<bool> happened_o2(false);
	std::atomic<bool> happened_o3(false);

	o1.connect<test_event>( [&](std::string s) {CHECK(s == "test"); happened_o1 = true; } );
	o2.connect<test_event>( [&](std::string s) {CHECK(s == "test"); happened_o2 = true; } );
	o2.connect<test_event2>( [&](std::string s) {CHECK(s == "test"); happened_o3 = true; } );

	CHECK(!happened_o1);
	CHECK(!happened_o2);
	CHECK(!happened_o3);

	h.emit<test_event>("test");

	wait_for_event(500, happened_o1);
	wait_for_event(500, happened_o2);

	CHECK(happened_o1);
	CHECK(happened_o2);
	CHECK(!happened_o3);
}

TEST_CASE("repeating_bc_event", "[event_system]") {

	event_context ec;
	broadcast_event_handler h;
	asio_broadcast_observer o(h, ec.context);
	std::atomic<int> counter(0);

	o.connect<simple_event>( [&]() { ++counter; } );
	CHECK(counter == 0);

	h.emit<simple_event>();
	wait_for_event(500, [&]{return counter > 0;});
	CHECK(counter == 1);

	h.emit<simple_event>();
	wait_for_event(500, [&]{return counter > 1;});
	CHECK(counter == 2);
}

TEST_CASE("remove_bc_event_not_exist", "[event_system]") {

	event_context ec;
	broadcast_event_handler h;
	asio_broadcast_observer o(h, ec.context);
	std::atomic<bool> happened(false);

	o.connect<simple_event>( [&]() { happened = true; } );

	o.disconnect(typeid(test_event));
	o.disconnect(typeid(test_event2));

	h.emit<simple_event>();
	wait_for_event(500, happened);
	CHECK(happened);
}

TEST_CASE("duplicated_bc_event", "[event_system]") {

	event_context ec;
	broadcast_event_handler h;
	asio_broadcast_observer o(h, ec.context);
	std::atomic<int> counter(0);

	o.connect<simple_event>( [&]() { counter++; } );
	o.connect<simple_event>( [&]() { counter++; } );
	o.connect<simple_event>( [&]() { counter++; } );

	h.emit<simple_event>();
	wait_for_event(500, [&]{return counter > 2;});
	CHECK(counter == 3);

	counter = 0;

	o.disconnect(typeid(simple_event)); // removes all
	h.emit<simple_event>();
	wait_for_event(500, [&]{return counter > 1;});
	CHECK(counter == 0);
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
	wait_for_event(500, [&]{return counter > 1;});
	CHECK(counter < 2);
}


}
}
