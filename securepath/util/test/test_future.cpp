// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/future.hpp>
#include <securepath/util/sync_wait.hpp>
#include <securepath/util/task.hpp>

#include <optional>
#include <stdexcept>
#include <thread>

namespace securepath::test {

TEST_CASE("future get returns the value", "[future]") {
	promise<int> pr;
	auto fut = pr.get_future();
	pr.set_value(7);
	CHECK(fut.get() == 7);
}

TEST_CASE("future exception is rethrown", "[future]") {
	promise<int> pr;
	pr.set_exception(std::make_exception_ptr(std::runtime_error("boom")));
	CHECK_THROWS_AS(pr.get_future().get(), std::runtime_error);
}

TEST_CASE("only the first completion of a promise wins", "[future]") {
	promise<int> pr;
	pr.set_value(1);
	pr.set_value(2);
	pr.set_exception(std::make_exception_ptr(std::runtime_error("boom")));
	CHECK(pr.get_future().get() == 1);
}

TEST_CASE("awaiting an already completed future resumes immediately", "[future]") {
	promise<int> pr;
	pr.set_value(7);
	auto get = [&]() -> task<int> {
		co_return co_await pr.get_future();
	};
	CHECK(sync_wait(get()) == 7);
}

TEST_CASE("awaiting suspends until the promise is completed", "[future]") {
	promise<int> pr;
	auto get = [&]() -> task<int> {
		co_return co_await pr.get_future();
	};
	std::jthread completer{[&] {
		pr.set_value(7);
	}};
	CHECK(sync_wait(get()) == 7);
}

TEST_CASE("future of void completes", "[future]") {
	promise<void> pr;
	auto get = [&]() -> task<void> {
		co_await pr.get_future();
	};
	pr.set_value();
	sync_wait(get());
	CHECK(true);
}

}
