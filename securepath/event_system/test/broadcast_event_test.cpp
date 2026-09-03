// SPDX-License-Identifier: MIT

// Broadcast handler/observer semantics through the asio-free
// event_loop_broadcast_observer; the asio observer's dispatch is covered in
// asio_broadcast_event_test.cpp. The subscription semantics under test here
// live in the shared bc_observer_impl.

#include "util.hpp"

#include <securepath/event_system/broadcast_event_handler.hpp>
#include <securepath/event_system/broadcast_observer.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/event_system/event_loop_broadcast_observer.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <atomic>
#include <string>

namespace securepath::event_system {
namespace test {
namespace {

struct test_event {
	using type = void(std::string);
};

struct test_event2 {
	using type = void(std::string);
};

struct simple_event {
	using type = void();
};

struct bc_receiver : event_loop_broadcast_observer {
	bc_receiver(broadcast_event_handler& bhandler, event_system::event_loop& loop)
	: event_loop_broadcast_observer(bhandler, loop)
	{
	}

	~bc_receiver() {
		stop_handler();
	}

	void on_test_event(std::string const& s) {
		string_matched = string_matched && s == "test";
		++test_count;
	}

	void on_test_event2(std::string const& s) {
		++test2_count;
	}

	void on_simple_event() {
		++simple_count;
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<test_event>(&bc_receiver::on_test_event)
				, event_dest<test_event2>(&bc_receiver::on_test_event2)
				, event_dest<simple_event>(&bc_receiver::on_simple_event) );
	}

	std::atomic<int> test_count{};
	std::atomic<int> test2_count{};
	std::atomic<int> simple_count{};
	std::atomic<bool> string_matched{true};
};

}

TEST_CASE("bc_simple_event", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r(h, loop);
	r.connect<test_event>();

	CHECK(r.test_count == 0);
	h.emit<test_event>("test");

	wait_for_event(500, [&]{ return r.test_count > 0; });
	CHECK(r.test_count == 1);
	CHECK(r.string_matched);
}

TEST_CASE("bc_observer_disconnect", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r(h, loop);
	r.connect<test_event>();
	r.disconnect(typeid(test_event));

	h.emit<test_event>("test");

	wait_for_event(500, [&]{ return r.test_count > 0; });
	CHECK(r.test_count == 0);
}

TEST_CASE("bc_correct_event_call", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r(h, loop);
	r.connect<test_event>();
	r.connect<test_event2>();
	r.connect<simple_event>();

	h.emit<test_event2>("test");

	wait_for_event(500, [&]{ return r.test2_count > 0; });
	CHECK(r.test_count == 0);
	CHECK(r.test2_count == 1);
	CHECK(r.simple_count == 0);
}

TEST_CASE("multiple_bc_observers_for_event", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r1(h, loop);
	bc_receiver r2(h, loop);
	bc_receiver r3(h, loop);

	r1.connect<test_event>();
	r2.connect<test_event>();
	r2.connect<test_event2>();

	h.emit<test_event>("test");

	wait_for_event(500, [&]{ return r1.test_count > 0 && r2.test_count > 0; });
	CHECK(r1.test_count == 1);
	CHECK(r2.test_count == 1);
	CHECK(r2.test2_count == 0);
	CHECK(r3.test_count == 0);
	CHECK(r1.string_matched);
	CHECK(r2.string_matched);
}

TEST_CASE("repeating_bc_event", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r(h, loop);
	r.connect<simple_event>();

	h.emit<simple_event>();
	wait_for_event(500, [&]{ return r.simple_count > 0; });
	CHECK(r.simple_count == 1);

	h.emit<simple_event>();
	wait_for_event(500, [&]{ return r.simple_count > 1; });
	CHECK(r.simple_count == 2);
}

TEST_CASE("remove_bc_event_not_exist", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r(h, loop);
	r.connect<simple_event>();

	r.disconnect(typeid(test_event));
	r.disconnect(typeid(test_event2));

	h.emit<simple_event>();
	wait_for_event(500, [&]{ return r.simple_count > 0; });
	CHECK(r.simple_count == 1);
}

TEST_CASE("duplicated_bc_event", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler h;
	bc_receiver r(h, loop);
	r.connect<simple_event>();
	r.connect<simple_event>();
	r.connect<simple_event>();

	h.emit<simple_event>();
	wait_for_event(500, [&]{ return r.simple_count > 2; });
	CHECK(r.simple_count == 3);

	r.simple_count = 0;
	r.disconnect(typeid(simple_event)); // removes all
	h.emit<simple_event>();
	wait_for_event(500, [&]{ return r.simple_count > 0; });
	CHECK(r.simple_count == 0);
}

}
}
