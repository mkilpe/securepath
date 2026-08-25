// SPDX-License-Identifier: MIT

#include "util.hpp"

#include <securepath/event_system/event_loop_broadcast_observer.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/log/log.hpp>

#include <iostream>

namespace securepath::event_system {
namespace test {

struct my_event {
	typedef void type(std::string);
};

struct event_test_class : event_handler {
	event_test_class(event_system::single_thread_event_loop& loop)
	: event_handler(loop)
	{}
	~event_test_class() {
		stop_handler();
	}
	void handle_event(std::unique_ptr<event_base> ev) override {
		happened = true;
	}

	std::atomic<bool> happened{};
};

TEST_CASE("simple_event_test", "[event_system]") {
	single_thread_event_loop loop;
	event_test_class obj(loop);
	obj.emit<my_event>("test");
	wait_for_event(500, obj.happened);
	CHECK(obj.happened);
}

TEST_CASE("disable_event_handler_test", "[event_system]") {
	single_thread_event_loop loop;
	event_test_class obj(loop);
	obj.stop_handler();
	obj.emit<my_event>("test");
	wait_for_event(500, obj.happened);
	CHECK(!obj.happened);
}


struct self_remove_test_class : event_handler {
	self_remove_test_class(event_system::single_thread_event_loop& loop)
	: event_handler(loop)
	{}
	~self_remove_test_class() {
		stop_handler();
	}
	void handle_event(std::unique_ptr<event_base> ev) override {
		++count;
		if(count == 1) {
			emit<my_event>("test1");
			emit<my_event>("test2");
			emit<my_event>("test3");
		} else if(count == 2) {
			stop_handler();
		}
	}

	std::atomic<int> count{};
};

TEST_CASE("self_remove_event_test", "[event_system]") {
	single_thread_event_loop loop;
	self_remove_test_class obj(loop);
	obj.emit<my_event>("test");
	std::this_thread::sleep_for(500ms);
	CHECK(obj.count == 2);
	CHECK(!obj.is_active());
}

struct string_event {
	typedef void type(std::string);
};

struct another_event {
	typedef void type(std::string, int);
};

struct some_event {
	typedef void type();
};

struct unknown_event {
	typedef void type();
};

struct dispatch_test_class : event_handler {
	dispatch_test_class(event_system::single_thread_event_loop& loop)
	: event_handler(loop)
	{}
	~dispatch_test_class() {
		stop_handler();
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<string_event>(&dispatch_test_class::on_string_event)
				, event_dest<another_event>(&dispatch_test_class::on_another_event)
				, event_dest<some_event>([this]{++some;}) );
	}
	void on_string_event(std::string const& s) {
		strings.push_back(s);
	}
	void on_another_event(std::string const& s, int i) {
		strings.push_back(s);
	}

	std::vector<std::string> strings;
	int some{};
};


TEST_CASE("dispatch_event_test", "[event_system]") {
	single_thread_event_loop loop;
	dispatch_test_class obj(loop);

	obj.emit<string_event>("test1");
	obj.emit<some_event>();
	obj.emit<another_event>("test2", 1);
	obj.emit<unknown_event>();
	std::this_thread::sleep_for(500ms);

	CHECK(obj.some == 1);
	CHECK(obj.strings == std::vector<std::string>{"test1", "test2"});
}

struct f_event {
	typedef void type();
};

class forwarding_test_class : public event_handler {
public:

	forwarding_test_class(dispatch_test_class& f)
	: event_handler(f.event_loop())
	, forward(f)
	{}

	~forwarding_test_class() {
		stop_handler();
	}

	void on_f_event() {
		++f_event_count;
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<f_event>(&forwarding_test_class::on_f_event)
				, event_forward(forward) );
	}

	dispatch_test_class& forward;
	std::atomic<int> f_event_count{};
};


TEST_CASE("dispatch_event_forwarding_test", "[event_system]") {
	single_thread_event_loop loop;
	dispatch_test_class obj(loop);
	forwarding_test_class forward(obj);

	forward.emit<f_event>();
	forward.emit<string_event>("test1");
	forward.emit<some_event>();
	forward.emit<another_event>("test2", 1);
	forward.emit<unknown_event>();
	std::this_thread::sleep_for(500ms);

	CHECK(forward.f_event_count == 1);
	CHECK(obj.some == 1);
	CHECK(obj.strings == std::vector<std::string>{"test1", "test2"});
}


struct timer_test_class : event_handler {
	using clock = std::chrono::steady_clock;

	timer_test_class(event_system::single_thread_event_loop& loop)
	: event_handler(loop)
	{}

	~timer_test_class() {
		stop_handler();
	}

	void start_timer1(int millis, bool single_shot) {
		h1 = event_handler::start_timer(std::chrono::milliseconds{millis}, single_shot);
	}
	void start_timer2(int millis, bool single_shot) {
		h2 = event_handler::start_timer(std::chrono::milliseconds{millis}, single_shot);
	}

	void on_timer(timer_handle h) {
		LOG_TRACE("on_timer");
		if(h == h1) {
			++timer1;
		} else if(h == h2) {
			++timer2;
		}
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<timer_event>(&timer_test_class::on_timer) );
	}

	timer_handle h1{};
	timer_handle h2{};

	std::atomic<int> timer1{};
	std::atomic<int> timer2{};
};

// test single shot
// test normal timer interval
// test multiple timers with single handler
// test stopping timer

TEST_CASE("timer_test_class", "[event_system]") {
	single_thread_event_loop loop;

	SECTION("normal timer") {
		timer_test_class test(loop);
		timer t;
		test.start_timer1(2000, false);
		wait_for_event(3000, [&]{ return test.timer1 != 0; });
		CHECK(test.timer1 == 1);
		CHECK(t.elapsed_milliseconds() > 1900);
		CHECK(t.elapsed_milliseconds() < 2100);
		wait_for_event(3000, [&]{ return test.timer1 == 2; });
		CHECK(t.elapsed_milliseconds() > 3900);
		CHECK(t.elapsed_milliseconds() < 4100);
	}
	SECTION("single shot") {
		timer_test_class test(loop);
		timer t;
		test.start_timer1(1000, true);
		wait_for_event(3000, [&]{ return test.timer1 != 0; });
		CHECK(test.timer1 == 1);
		CHECK(t.elapsed_milliseconds() > 900);
		CHECK(t.elapsed_milliseconds() < 1100);
		std::this_thread::sleep_for(2s);
		CHECK(test.timer1 == 1);
	}
	SECTION("stop timer") {
		timer_test_class test(loop);
		timer t;
		test.start_timer1(1000, false);
		wait_for_event(3000, [&]{ return test.timer1 != 0; });
		CHECK(test.timer1 == 1);
		CHECK(t.elapsed_milliseconds() > 900);
		CHECK(t.elapsed_milliseconds() < 1100);
		test.stop_timer(test.h1);
		std::this_thread::sleep_for(2s);
		CHECK(test.timer1 == 1);
	}
	SECTION("two timers") {
		timer_test_class test(loop);
		timer t1, t2;
		test.start_timer1(1000, false);
		test.start_timer2(1500, false);
		wait_for_event(5000, [&]{ return test.timer1 == 4; });
		CHECK(test.timer1 == 4);
		CHECK(test.timer2 == 2);
	}
}

struct broadcast_test_class : event_loop_broadcast_observer {

	broadcast_test_class(broadcast_event_handler& bhandler, event_system::single_thread_event_loop& loop)
	: event_loop_broadcast_observer(bhandler, loop)
	{
		connect<string_event>();
		connect<another_event>();
	}

	~broadcast_test_class() {
		stop_handler();
	}

	void on_string_event(std::string const& s) {
		strings.push_back(s);
		++num;
	}

	void on_another_event(std::string const& s, int i) {
		strings.push_back(s);
		++num;
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<string_event>(&broadcast_test_class::on_string_event)
				, event_dest<another_event>(&broadcast_test_class::on_another_event) );
	}

	std::atomic<int> num{};
	std::vector<std::string> strings;
};

TEST_CASE("broadcast integration test", "[event_system]") {
	single_thread_event_loop loop;
	broadcast_event_handler bhandler;

	broadcast_test_class test(bhandler, loop);
	bhandler.emit<string_event>("1");
	bhandler.emit<string_event>("2");
	bhandler.emit<another_event>("3", 1);
	bhandler.emit<another_event>("4", 1);

	wait_for_event(1000, [&]{ return test.num == 4; });
	REQUIRE(test.num == 4);
	CHECK(test.strings[0] == "1");
	CHECK(test.strings[1] == "2");
	CHECK(test.strings[2] == "3");
	CHECK(test.strings[3] == "4");
}

}
}
