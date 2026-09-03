// SPDX-License-Identifier: MIT

#pragma once

#include "audio_buffer.hpp"
#include <securepath/util/string_util.hpp>

#include <memory>
#include <string>
#include <vector>

namespace securepath::audio {

class audio_device_info  {
public:
	audio_device_info(bool is_play, std::string name, std::string desc)
	: device_(std::move(name))
	, desc_(std::move(desc))
	, is_play_device_(is_play)
	{
	}

	virtual ~audio_device_info() {}

	std::string const& device() const { return device_; }
	std::string const& description() const { return desc_; }
	bool is_play_device() const { return is_play_device_; }

protected:
	std::string device_;
	std::string desc_;
	bool is_play_device_;
};

typedef std::shared_ptr<audio_device_info> audio_device_info_ptr;
typedef std::vector<audio_device_info_ptr> adinfos;

namespace audio_device_t {
	enum type { play = 1, capture = 2 };
}
typedef audio_device_t::type audio_device_type;

enum class stop_type { force, drain };

namespace audio_device_mode {
	enum type {
		none = 0x0,
		notifications = 0x1
	};
}

struct mode;
class audio_device {
public:
	virtual void start() = 0;
	virtual void stop(stop_type = stop_type::force) = 0;

	virtual device_config config() const = 0;

	//in samples
	virtual std::size_t buffer_size() const = 0;
	virtual std::size_t avail() const = 0;

	//wait for notification mode
	virtual bool wait() = 0;

	virtual int supported_modes() const = 0;
	virtual void set_mode(mode const&) = 0;

	virtual ~audio_device() {}
};

class audio_capture_device : public audio_device {
public:
	//returns read samples
	virtual std::size_t read(audio_buffer&) = 0;
};

class audio_play_device : public audio_device {
public:
	//returns written samples
	virtual std::size_t write(audio_buffer&) = 0;
};

typedef std::unique_ptr<audio_capture_device> audio_capture_device_ptr;
typedef std::unique_ptr<audio_play_device> audio_play_device_ptr;

}

