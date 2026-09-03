// SPDX-License-Identifier: MIT

#include "alsa.hpp"
#include <securepath/audio/audio_lib/audio_device_modes.hpp>
#include <securepath/audio/audio_lib/util.hpp>

#include <securepath/log/log.hpp>

#include <atomic>
#include <iostream>
#include <cstring>
#include <mutex>

#include <alsa/asoundlib.h>

namespace securepath::audio {
namespace {

struct alsa_device_info : audio_device_info {
public:
	alsa_device_info(std::string const& device, std::string const& desc, bool play_device)
	: audio_device_info(play_device, device, desc)
	{
	}
};

struct hw_params {
	hw_params() : params() {
		int err = snd_pcm_hw_params_malloc(&params);
		if(err != 0) {
			LOG_TRACE("failed to allocate device parameters: {}", snd_strerror(err));
			throw std::runtime_error("failed to allocate device parameters");
		}
	}
	~hw_params() {
		snd_pcm_hw_params_free(params);
	}

	snd_pcm_hw_params_t* params;
};

struct sw_params {
	sw_params() : params() {
		int err = snd_pcm_sw_params_malloc(&params);
		if(err != 0) {
			LOG_TRACE("failed to allocate device parameters: {}", snd_strerror(err));
			throw std::runtime_error("failed to allocate device parameters");
		}
	}
	~sw_params() {
		snd_pcm_sw_params_free(params);
	}

	snd_pcm_sw_params_t* params;
};

snd_pcm_format_t format_map[][2] =
	{ {SND_PCM_FORMAT_S8, SND_PCM_FORMAT_S8}
	, {SND_PCM_FORMAT_U8, SND_PCM_FORMAT_U8}
	, {SND_PCM_FORMAT_S16_LE, SND_PCM_FORMAT_S16_BE}
	, {SND_PCM_FORMAT_FLOAT, SND_PCM_FORMAT_FLOAT}};

snd_pcm_format_t map_to_alsa_format(audio_format const& f) {
	if(f.type < 0 || f.type >= sizeof(format_map)/sizeof(snd_pcm_format_t[2])
		|| (f.endian != std::endian::little && f.endian != std::endian::big))
	{
		throw std::runtime_error("invalid format");
	}
	std::size_t const endian_idx = f.endian == std::endian::little ? 0 : 1;
	return format_map[f.type][endian_idx];
}

// ALSA counts in frames (one sample per channel across the interleave); the
// audio_device interface counts in samples. Convert at every ALSA boundary.
std::size_t to_frames(audio_format const& f, std::size_t samples) {
	return samples / f.channels;
}

std::size_t to_samples(audio_format const& f, std::size_t frames) {
	return frames * f.channels;
}

// owns an open snd_pcm_t and closes it on destruction, so a constructor throw
// after the open cannot leak the handle
class pcm_handle {
public:
	pcm_handle() = default;
	~pcm_handle() {
		if(handle_) {
			snd_pcm_close(handle_);
		}
	}
	pcm_handle(pcm_handle const&) = delete;
	pcm_handle& operator=(pcm_handle const&) = delete;

	int open(char const* device, snd_pcm_stream_t stream, int mode) {
		return snd_pcm_open(&handle_, device, stream, mode);
	}

	operator snd_pcm_t*() const { return handle_; }

private:
	snd_pcm_t* handle_{};
};

static void check_config(int err, char const* what) {
	if(err < 0) {
		LOG_TRACE("failed to configure parameters ({}): {}", what, snd_strerror(err));
		throw std::runtime_error("failed to configure parameters");
	}
}

device_config configure(snd_pcm_t* handle, device_config config) {
	hw_params p;

	LOG_TRACE("trying configuration: {}", config);

	check_config(snd_pcm_hw_params_any(handle, p.params), "any");
	check_config(snd_pcm_hw_params_set_rate_resample(handle, p.params, 1), "resample");
	check_config(snd_pcm_hw_params_set_access(handle, p.params, SND_PCM_ACCESS_RW_INTERLEAVED), "access");
	check_config(snd_pcm_hw_params_set_format(handle, p.params, map_to_alsa_format(config.format)), "format");
	check_config(snd_pcm_hw_params_set_channels(handle, p.params, config.format.channels), "channels");
	check_config(snd_pcm_hw_params_set_rate(handle, p.params, config.format.samples_per_second, 0), "rate");

	snd_pcm_uframes_t buffer_size = to_frames(config.format, config.buffer_size);
	check_config(snd_pcm_hw_params_set_buffer_size_near(handle, p.params, &buffer_size), "buffer");
	config.buffer_size = to_samples(config.format, buffer_size);

	int dir = 0;
	snd_pcm_uframes_t period_size = to_frames(config.format, config.period_size);
	check_config(snd_pcm_hw_params_set_period_size_near(handle, p.params, &period_size, &dir), "period");
	config.period_size = to_samples(config.format, period_size);

	check_config(snd_pcm_hw_params(handle, p.params), "apply");

	LOG_TRACE("using configuration: {}", config);

	return config;
}

void configure_avail_min(snd_pcm_t* handle, audio_format const& format, std::size_t samples) {
	sw_params p;
	int err = snd_pcm_sw_params_current(handle, p.params);
	if(err < 0) {
		LOG_TRACE("failed to configure parameters: {}", snd_strerror(err));
		throw std::runtime_error("failed to configure parameters");
	}

	LOG_TRACE("Setting avail min to {} samples", samples);

	err = snd_pcm_sw_params_set_avail_min(handle, p.params, to_frames(format, samples));
	if(err < 0) {
		LOG_TRACE("failed to configure parameters: {}", snd_strerror(err));
		throw std::runtime_error("failed to configure parameters");
	}

	err = snd_pcm_sw_params(handle, p.params);
	if(err < 0) {
		LOG_TRACE("failed to set software parameters: {}", snd_strerror(err));
		throw std::runtime_error("failed to set software parameters");
	}
}

}

class alsa_play_device : public audio_play_device {
public:
	alsa_play_device(std::string const& device, device_config config)
	: device_config_(config)
	{
		int err = handle_.open(device.c_str(), SND_PCM_STREAM_PLAYBACK, 0/*SND_PCM_NONBLOCK*/);
		if(err != 0) {
			LOG_TRACE("cannot open audio device for playback: {}", snd_strerror(err));
			throw std::runtime_error("failed to open device for playback");
		}

		device_config_ = configure(handle_, config);

		hw_params hp;
		snd_pcm_hw_params_current(handle_, hp.params);
		can_pause_ = snd_pcm_hw_params_can_pause(hp.params);
		LOG_INFO("ALSA: can_pause={}", can_pause_);
	}


	void start() {
		auto state = snd_pcm_state(handle_);
		LOG_TRACE("ALSA: start, state={}", snd_pcm_state_name(state));

		if(state == SND_PCM_STATE_RUNNING) {
			running_ = true;
			return;
		}
		if(state == SND_PCM_STATE_PAUSED) {
			int err = snd_pcm_pause(handle_, 0);
			if(err == 0) {
				running_ = true;
				return;
			}
			LOG_TRACE("ALSA: resume from pause failed: {}, falling back to prepare", snd_strerror(err));
		}
		if(state != SND_PCM_STATE_PREPARED) {
			int err = snd_pcm_prepare(handle_);
			if(err != 0) {
				LOG_TRACE("failed to prepare play: {}", snd_strerror(err));
				throw std::runtime_error("failed to prepare play");
			}
		}
		int err = snd_pcm_start(handle_);
		if(err != 0) {
			LOG_TRACE("failed to start play: {}", snd_strerror(err));
			throw std::runtime_error("failed to start play");
		}
		running_ = true;
	}

	void stop(stop_type s) {
		running_ = false;
		if(s == stop_type::force && can_pause_) {
			int err = snd_pcm_pause(handle_, 1);
			if(err == 0) {
				return;
			}
			LOG_TRACE("ALSA: pause failed: {}, falling back to drop", snd_strerror(err));
		}
		int err = s == stop_type::force
			? snd_pcm_drop(handle_)
			: snd_pcm_drain(handle_);
		if(err != 0) {
			LOG_TRACE("failed to stop play: {}", snd_strerror(err));
			throw std::runtime_error("failed to stop play");
		}
	}

	virtual device_config config() const {
		return device_config_;
	}

	virtual std::size_t buffer_size() const {
		return device_config_.buffer_size;
	}

	virtual std::size_t avail() const {
		auto v = snd_pcm_avail_update(handle_);
		if(v == -EPIPE) {
			return buffer_size();
		}
		if(v < 0) {
			v = 0;
		}
		return to_samples(device_config_.format, v);
	}

	void set_notification(std::size_t samples) {
		configure_avail_min(handle_, device_config_.format, samples);
		int err = snd_pcm_prepare(handle_);
		if(err != 0) {
			LOG_TRACE("cannot prepare device for play: {}", snd_strerror(err));
			throw std::runtime_error("cannot prepare device for play");
		}

		int res = snd_pcm_poll_descriptors_count(handle_);
		if(res <= 0) {
			LOG_TRACE("failed to get poll descriptors count from ALSA: {}", snd_strerror(res));
			throw std::runtime_error("failed to get poll descriptors count from ALSA");
		}
		fds_.resize(res);

		res = snd_pcm_poll_descriptors(handle_, fds_.data(), fds_.size());
		if(res < 0) {
			LOG_TRACE("failed to get poll descriptors from ALSA: {}", snd_strerror(res));
			throw std::runtime_error("failed to get poll descriptors from ALSA");
		}
	}

	virtual int supported_modes() const {
		return audio_device_mode::notifications;
	}

	virtual void set_mode(mode const& m) {
		if(notification_mode const* p = dynamic_cast<notification_mode const*>(&m)) {
			set_notification(p->samples);
		}
	}

	bool wait() {
		unsigned short revents = 0;

		while(running_ && !(revents & (POLLERR|POLLOUT))) {
			if(poll(fds_.data(), fds_.size(), 20) > 0) {
				if(snd_pcm_poll_descriptors_revents(handle_, fds_.data(), fds_.size(), &revents) != 0) {
					LOG_TRACE("snd_pcm_poll_descriptors_revents failed");
				}
			}
		}

		return revents & POLLOUT;
	}

	virtual std::size_t write(audio_buffer& b) {
		auto const& fmt = device_config_.format;
		int frames = snd_pcm_writei(handle_, b.begin<uint8_t>(), to_frames(fmt, b.used_samples()));
		if(frames < 0) {
			if(frames == -EAGAIN) {
				LOG_TRACE("play device EAGAIN");
			} else if(frames == -EPIPE || frames == -ESTRPIPE) {
				LOG_TRACE("play device recover ({})", snd_strerror(frames));
				snd_pcm_recover(handle_, frames, 0);
				frames = snd_pcm_writei(handle_, b.begin<uint8_t>(), to_frames(fmt, b.used_samples()));
				if(frames < 0) {
					LOG_TRACE("retry write failed: {}", snd_strerror(frames));
					frames = 0;
				}
				if(snd_pcm_state(handle_) == SND_PCM_STATE_PREPARED) {
					snd_pcm_start(handle_);
				}
			} else {
				LOG_TRACE("failed to write to play device: {}", snd_strerror(frames));
				throw std::runtime_error("failed to write to play device");
			}
			if(frames < 0) {
				frames = 0;
			}
		}
		std::size_t samples = to_samples(fmt, frames);
		b.consume_samples(samples);
		return samples;
	}
private:
	device_config device_config_;
	pcm_handle handle_;
	std::vector<pollfd> fds_;
	std::atomic<bool> running_ = false;
	bool can_pause_ = false;
};

class alsa_capture_device : public audio_capture_device  {
public:
	alsa_capture_device(std::string const& device, device_config config)
	: device_config_(config)
	{
		int err = handle_.open(device.c_str(), SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);
		if(err != 0) {
			LOG_TRACE("cannot open audio device for capture: {}", snd_strerror(err));
			throw std::runtime_error("failed to open device for capture");
		}

		device_config_ = configure(handle_, config);

		/*err = snd_pcm_prepare(handle_);
		if(err != 0) {
			LOG_TRACE("cannot prepare device for capture: {}", snd_strerror(err));
			throw std::runtime_error("cannot prepare device for capture");
		}*/
	}


	void start() {
		running_ = true;
		if(snd_pcm_state(handle_) == SND_PCM_STATE_PREPARED) {
			int err = snd_pcm_start(handle_);
			if(err != 0) {
				LOG_TRACE("failed to start capture: {}", snd_strerror(err));
				throw std::runtime_error("failed to start play");
			}
		}
	}

	void stop(stop_type s) {
		running_ = false;
		int err = s == stop_type::force
			? snd_pcm_drop(handle_)
			: snd_pcm_drain(handle_);
		if(err != 0) {
			LOG_TRACE("failed to stop capture: {}", snd_strerror(err));
			throw std::runtime_error("failed to stop capture");
		}
	}

	virtual device_config config() const {
		return device_config_;
	}

	virtual std::size_t buffer_size() const {
		return device_config_.buffer_size;
	}

	virtual std::size_t avail() const {
		auto v = snd_pcm_avail_update(handle_);
		if(v < 0) {
			v = 0;
		}
		return to_samples(device_config_.format, v);
	}

	void set_notification(std::size_t samples) {
		configure_avail_min(handle_, device_config_.format, samples);
		int err = snd_pcm_prepare(handle_);
		if(err != 0) {
			LOG_TRACE("cannot prepare device for capture: {}", snd_strerror(err));
			throw std::runtime_error("cannot prepare device for capture");
		}

		int res = snd_pcm_poll_descriptors_count(handle_);
		if(res <= 0) {
			LOG_TRACE("failed to get poll descriptors count from ALSA: {}", snd_strerror(res));
			throw std::runtime_error("failed to get poll descriptors count from ALSA");
		}
		fds_.resize(res);

		res = snd_pcm_poll_descriptors(handle_, fds_.data(), fds_.size());
		if(res < 0) {
			LOG_TRACE("failed to get poll descriptors from ALSA: {}", snd_strerror(res));
			throw std::runtime_error("failed to get poll descriptors from ALSA");
		}
	}

	virtual std::size_t read(audio_buffer& b) {
		auto const& fmt = device_config_.format;
		int avail_frames = snd_pcm_avail_update(handle_);
		if(avail_frames < 0) {
			// xrun surfaces here as a negative avail; without recovery the
			// capture stream stays wedged for good
			LOG_TRACE("capture device recover ({})", snd_strerror(avail_frames));
			snd_pcm_recover(handle_, avail_frames, 0);
			avail_frames = 0;
		}
		std::size_t samples = 0;
		if(avail_frames > 0) {
			auto to_read = std::min<std::size_t>(avail_frames, to_frames(fmt, b.free_samples()));
			int frames = snd_pcm_readi(handle_, b.free_begin<uint8_t>(), to_read);
			if(frames < 0) {
				if(frames == -EPIPE || frames == -ESTRPIPE) {
					snd_pcm_recover(handle_, frames, 0);
				} else {
					LOG_TRACE("failed to read from capture device: {}", snd_strerror(frames));
					throw std::runtime_error("failed to read from capture device");
				}
				frames = 0;
			}
			samples = to_samples(fmt, frames);
			b.conserve_samples(samples);
		}
		return samples;
	}

	virtual int supported_modes() const {
		return audio_device_mode::notifications;
	}

	virtual void set_mode(mode const& m) {
		if(notification_mode const* p = dynamic_cast<notification_mode const*>(&m)) {
			set_notification(p->samples);
		}
	}

	bool wait() {
		unsigned short revents = 0;

		while(running_ && !(revents & (POLLERR|POLLIN))) {
			if(poll(fds_.data(), fds_.size(), 20) > 0) {
				if(snd_pcm_poll_descriptors_revents(handle_, fds_.data(), fds_.size(), &revents) != 0) {
					LOG_TRACE("snd_pcm_poll_descriptors_revents failed");
				}
			} else {
				LOG_TRACE("poll failed");
			}
		}

		return revents & POLLIN;
	}

private:
	device_config device_config_;
	pcm_handle handle_;
	std::vector<pollfd> fds_;
	std::atomic<bool> running_ = false;
};

std::string alsa_audio_interface::name() const {
	return "ALSA";
}

adinfos alsa_audio_interface::enumerate_devices(audio_device_type type) const
{
	adinfos devices;
	void** hints;

	if(snd_device_name_hint(-1, "pcm", &hints) != 0) {
		throw std::runtime_error("failed to enumerate audio devices");
	}

	for(void** h = hints;*h;++h) {
		char* name = snd_device_name_get_hint(*h, "NAME");
		char* desc = snd_device_name_get_hint(*h, "DESC");
		char* io = snd_device_name_get_hint(*h, "IOID"); //Input or Output or NULL for both

		std::string name_str = name ? name : "";
		std::string desc_str = desc ? desc : "";
		std::string io_str = io ? io : "";

		free(io);
		free(desc);
		free(name);

		LOG_INFO("alsa pcm device: {}:{}:{}", name_str, io_str, desc_str);

		if((type & audio_device_t::play) && (io_str.empty() || io_str == "Output")) {
			devices.push_back(std::make_shared<alsa_device_info>(name_str, desc_str, true));
		}
		if((type & audio_device_t::capture) && (io_str.empty() || io_str == "Input")) {
			devices.push_back(std::make_shared<alsa_device_info>(name_str, desc_str, false));
		}
	}
	snd_device_name_free_hint(hints);

	return devices;
}

audio_play_device_ptr alsa_audio_interface::play_device(device_config const& config, audio_device_info_ptr info) const {
	alsa_device_info* p = info ? dynamic_cast<alsa_device_info*>(info.get()) : nullptr;
	if(info && (!p || !info->is_play_device())) {
		throw std::runtime_error("invalid audio play device info");
	}
	return audio_play_device_ptr(new alsa_play_device(p ? p->device() : "default", config));
}

audio_capture_device_ptr alsa_audio_interface::capture_device(device_config const& config, audio_device_info_ptr info) const {
	alsa_device_info* p = info ? dynamic_cast<alsa_device_info*>(info.get()) : nullptr;
	if(info && (!p || info->is_play_device())) {
		throw std::runtime_error("invalid audio capture device info");
	}
	return audio_capture_device_ptr(new alsa_capture_device(p ? p->device() : "default", config));
}

}
