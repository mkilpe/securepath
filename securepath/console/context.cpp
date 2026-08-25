// SPDX-License-Identifier: MIT

#include "context.hpp"
#include "curses.hpp"
#include "widget.hpp"

#include <securepath/log/log.hpp>

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace securepath::console {

struct context::impl {
	impl(std::mutex& m, std::condition_variable& c)
	: mutex_(m)
	, cond_(c)
	, win_(initscr())
	{
		if(!win_) {
			throw std::runtime_error("failed to initialise curses");
		}

		keypad(stdscr, TRUE);
	}

	~impl() {
		std::unique_lock l{mutex_};
		while(running_) {
			cond_.wait(l);
		}
	}

	void wait_for_processing(std::unique_lock<std::mutex>& lock) {
		while(processing_) {
			process_cond_.wait(lock);
		}
	}

	void draw_widgets(std::unique_lock<std::mutex>& lock) {
		wait_for_processing(lock);
		processing_ = true;
		auto focus = focus_widget_.lock();
		lock.unlock();
		for(auto& w : widgets_) {
			if(w.second != focus) {
				w.second->draw();
			}
		}
		//draw the focus widget last so it gets the cursor
		if(focus) {
			focus->draw();
		}
		lock.lock();
		processing_ = false;
		process_cond_.notify_one();
	}

	void handle_input(std::unique_lock<std::mutex>& lock, input const& in) {
		auto w = focus_widget_.lock();
		if(w) {
			processing_ = true;
			lock.unlock();
			w->key_event(in);
			lock.lock();
			processing_ = false;
			process_cond_.notify_one();
		}
	}


	std::mutex& mutex_;
	std::condition_variable& cond_;
	WINDOW* win_;
	bool running_{};
	std::map<widget*, std::shared_ptr<widget>> widgets_;
	std::weak_ptr<widget> focus_widget_;
	bool processing_{};
	bool redraw_{};
	std::condition_variable process_cond_;
};

context::context()
: impl_(std::make_unique<impl>(mutex_, cond_))
{
}

context::~context()
{
	endwin();
}

void context::set_mode(int m)
{
	LOG_TRACE("mode={}", m);

	if(m & mode::raw) {
		raw();
	} else {
		noraw();
	}
	if(m & mode::cbreak) {
		cbreak();
	} else {
		nocbreak();
	}
	if(m & mode::noecho) {
		noecho();
	} else {
		echo();
	}
	if(m & mode::nodelay) {
		nodelay(stdscr, true);
	}
	if(m & mode::colours) {
		LOG_TRACE("enabling colours");
		if(start_color() == ERR) {
			throw std::runtime_error("failed to enable colours");
		}
	}
}

void context::enable_cursor(bool enable) {
	curs_set(enable ? 1 : 0);
}

point context::screen_size() const {
	point p;
	getmaxyx(stdscr, p.y, p.x);
	return p;
}

static input map_to_input_key(std::wint_t key) {
	input res;
	switch(key) {
		case KEY_DOWN: {
				res.key = input_key::down_arrow;
				break;
			}
		case KEY_UP: {
				res.key = input_key::up_arrow;
				break;
			}
		case KEY_LEFT: {
				res.key = input_key::left_arrow;
				break;
			}
		case KEY_RIGHT: {
				res.key = input_key::right_arrow;
				break;
			}
		case KEY_HOME: {
				res.key = input_key::home;
				break;
			}
		case KEY_END: {
				res.key = input_key::end;
				break;
			}
		case KEY_DC: {
				res.key = input_key::del;
				break;
			}
		case KEY_NPAGE: {
				res.key = input_key::page_down;
				break;
			}
		case KEY_PPAGE: {
				res.key = input_key::page_up;
				break;
			}
		case KEY_BACKSPACE: {
				res.key = input_key::backspace;
				break;
			}
		case KEY_IC: {
				res.key = input_key::insert;
				break;
			}
		case KEY_F(1): {
				res.key = input_key::f1;
				break;
			}
		case KEY_F(2): {
				res.key = input_key::f2;
				break;
			}
		case KEY_F(3): {
				res.key = input_key::f3;
				break;
			}
		case KEY_F(4): {
				res.key = input_key::f4;
				break;
			}
		case KEY_F(5): {
				res.key = input_key::f5;
				break;
			}
		case KEY_F(6): {
				res.key = input_key::f6;
				break;
			}
		case KEY_F(7): {
				res.key = input_key::f7;
				break;
			}
		case KEY_F(8): {
				res.key = input_key::f8;
				break;
			}
		case KEY_F(9): {
				res.key = input_key::f9;
				break;
			}
		case KEY_F(10): {
				res.key = input_key::f10;
				break;
			}
		case KEY_F(11): {
				res.key = input_key::f11;
				break;
			}
		case KEY_F(12): {
				res.key = input_key::f12;
				break;
			}

	};
	return res;
}

input context::get_input() {
	input ret;
	std::wint_t key_code = 0;
	int res = get_wch(&key_code);
	if(res == OK) {
		if(key_code == 27) {
			ret.key = input_key::esc;
		} else {
			ret.ch = key_code;
		}
	} else if(res == KEY_CODE_YES) {
		ret = map_to_input_key(key_code);
	}
	return ret;
}

void context::thread_entry() {
	std::unique_lock l{impl_->mutex_};
	my_thread_id_ = std::this_thread::get_id();
	refresh();
	impl_->draw_widgets(l);
	while(!quit_) {
		input ch;
		{
			l.unlock();
			ch = get_input();
			l.lock();
		}
		if(ch.is_valid()) {
			impl_->handle_input(l, ch);
			impl_->redraw_ = true;
		}
		if(impl_->redraw_) {
			impl_->draw_widgets(l);
			impl_->redraw_ = false;
		}
		if(!handle_events(l) && !ch.is_valid()) {
			cond_.wait_for(l, std::chrono::milliseconds(50));
		}
	}
	impl_->running_ = false;
	impl_->cond_.notify_one();
}

bool context::handle_events(std::unique_lock<std::mutex>& l) {
	int i = 0;
	while(process_single_event(l) && ++i != 100) {}
	return !events_.empty();
}

void context::redraw() {
	std::unique_lock l{mutex_};
	impl_->redraw_ = true;
}

void context::quit() {
	std::unique_lock l{mutex_};
	quit_ = true;
	cond_.notify_one();
}

void context::add_widget(std::shared_ptr<widget> p) {
	std::unique_lock l{impl_->mutex_};
	impl_->wait_for_processing(l);
	impl_->widgets_[&*p] = p;
}

void context::remove_widget(widget* p) {
	std::unique_lock l{impl_->mutex_};
	impl_->wait_for_processing(l);
	impl_->widgets_.erase(p);
}

std::weak_ptr<widget> context::set_focus(std::weak_ptr<widget> w) {
	std::unique_lock l{impl_->mutex_};
	w.swap(impl_->focus_widget_);
	return w;
}

}