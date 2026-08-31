// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/resume_on.hpp>
#include <securepath/util/sync_wait.hpp>
#include <securepath/util/task.hpp>

#include <condition_variable>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace securepath::test {

namespace {

/// runs submitted work on a single background thread until destroyed
class executor_thread {
public:
	struct handle {
		void execute(std::function<void()> work) const {
			self->post(std::move(work));
		}

		executor_thread* self{};
	};

	executor_thread()
	: thread_([this](std::stop_token stop) { run(stop); })
	{
	}

	~executor_thread() {
		{
			std::unique_lock l{mutex_};
			thread_.request_stop();
		}
		cv_.notify_all();
	}

	handle executor() noexcept {
		return handle{this};
	}

	std::thread::id thread_id() const noexcept {
		return thread_.get_id();
	}

private:
	void post(std::function<void()> work) {
		{
			std::unique_lock l{mutex_};
			queue_.push_back(std::move(work));
		}
		cv_.notify_all();
	}

	void run(std::stop_token stop) {
		std::unique_lock l{mutex_};
		while(!stop.stop_requested()) {
			cv_.wait(l, [&] { return stop.stop_requested() || !queue_.empty(); });
			while(!queue_.empty()) {
				auto work = std::move(queue_.front());
				queue_.erase(queue_.begin());
				l.unlock();
				work();
				l.lock();
			}
		}
	}

private:
	std::mutex mutex_;
	std::condition_variable cv_;
	std::vector<std::function<void()>> queue_;
	std::jthread thread_;
};

static_assert(executor<executor_thread::handle>);

task<int> answer_42() {
	co_return 42;
}

task<int> throwing_task() {
	throw std::runtime_error("boom");
	co_return 0;
}

}

TEST_CASE("resume_on resumes the coroutine on the executor", "[resume_on]") {
	executor_thread ex;
	promise<int> pr;
	std::thread::id resumed_on{};
	auto run = [&]() -> task<int> {
		int value = co_await resume_on(ex.executor(), pr.get_future());
		resumed_on = std::this_thread::get_id();
		co_return value;
	};
	std::jthread completer{[&] { pr.set_value(7); }};
	CHECK(sync_wait(run()) == 7);
	CHECK(resumed_on == ex.thread_id());
}

TEST_CASE("resume_on hops even when the awaitable is already complete", "[resume_on]") {
	executor_thread ex;
	promise<int> pr;
	pr.set_value(7);
	std::thread::id resumed_on{};
	auto run = [&]() -> task<void> {
		int value = co_await resume_on(ex.executor(), pr.get_future());
		resumed_on = std::this_thread::get_id();
		CHECK(value == 7);
	};
	sync_wait(run());
	CHECK(resumed_on == ex.thread_id());
}

TEST_CASE("resume_on passes a task result through", "[resume_on]") {
	executor_thread ex;
	CHECK(sync_wait(resume_on(ex.executor(), answer_42())) == 42);
}

TEST_CASE("resume_on rethrows on the executor", "[resume_on]") {
	executor_thread ex;
	std::thread::id caught_on{};
	auto run = [&]() -> task<void> {
		try {
			co_await resume_on(ex.executor(), throwing_task());
		} catch(std::runtime_error const&) {
			caught_on = std::this_thread::get_id();
		}
	};
	sync_wait(run());
	CHECK(caught_on == ex.thread_id());
}

TEST_CASE("resume_on works with future of void", "[resume_on]") {
	executor_thread ex;
	promise<void> pr;
	pr.set_value();
	sync_wait(resume_on(ex.executor(), pr.get_future()));
	CHECK(true);
}

}
