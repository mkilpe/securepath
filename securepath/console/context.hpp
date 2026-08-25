// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"
#include <securepath/event_system/event_loop.hpp>

#include <optional>
#include <memory>

namespace securepath::console {

namespace mode {
enum type {
	none    = 0x0,
	raw     = 0x1,
	cbreak  = 0x2,
	noecho  = 0x4,
	colours = 0x8,
	nodelay = 0x10
};
}
using mode_type = mode::type;

class widget;

class context : public event_system::basic_event_loop {
public:
	context();
	~context();

	void set_mode(int);

	void enable_cursor(bool = true);

	point screen_size() const;

	input get_input();
	void thread_entry();

	void add_widget(std::shared_ptr<widget>);
	void remove_widget(widget*);
	std::weak_ptr<widget> set_focus(std::weak_ptr<widget>);
	void redraw();

	void quit();

private:
	bool handle_events(std::unique_lock<std::mutex>&);
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}