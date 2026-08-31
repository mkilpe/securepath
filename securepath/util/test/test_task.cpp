// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/sync_wait.hpp>
#include <securepath/util/task.hpp>

#include <stdexcept>
#include <utility>

namespace securepath::test {

namespace {

task<int> answer() {
	co_return 42;
}

task<int> add_one(task<int> t) {
	co_return co_await std::move(t) + 1;
}

task<void> set_flag(bool& flag) {
	flag = true;
	co_return;
}

task<int> throwing(bool do_throw) {
	if(do_throw) {
		throw std::runtime_error("boom");
	}
	co_return 0;
}

}

TEST_CASE("task runs lazily when awaited", "[task]") {
	bool flag = false;
	auto t = set_flag(flag);
	CHECK(!flag);
	sync_wait(std::move(t));
	CHECK(flag);
}

TEST_CASE("task result is returned through co_await", "[task]") {
	CHECK(sync_wait(answer()) == 42);
	CHECK(sync_wait(add_one(answer())) == 43);
}

TEST_CASE("task exception propagates to the awaiter", "[task]") {
	CHECK_THROWS_AS(sync_wait(throwing(true)), std::runtime_error);
	CHECK_THROWS_AS(sync_wait(add_one(throwing(true))), std::runtime_error);
}

}
