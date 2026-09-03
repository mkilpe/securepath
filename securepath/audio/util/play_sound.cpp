// SPDX-License-Identifier: MIT

#include "play_sound.hpp"
#include "audio_data.hpp"

#include <securepath/audio/audio_lib/audio_interface.hpp>
#include <securepath/audio/audio_lib/util.hpp>

#include <cstring>
#include <thread>

namespace securepath::audio {

play_sound::play_sound(audio::audio_play_device_ptr p)
: playback_(std::move(p))
{
}

void play_sound::run(octet_vector const& data) {
	auto f = playback_->config().format;
	std::size_t bsize = audio::samples_to_duration(f, playback_->buffer_size()) * 1000;
	audio::audio_buffer buffer(f, data);

	for(;!buffer.empty();) {
		playback_->write(buffer);
		if(!buffer.empty()) {
			//note: not optimal, better way to do this?
			std::this_thread::sleep_for(std::chrono::milliseconds(bsize/2));
		}
	}
}

void play_sound::wait() {
	playback_->stop(audio::stop_type::drain);
}

void play_sound_on_default_device(audio::audio_format format, octet_vector const& data) {
	auto default_device = audio::create_default_audio_interface();
	play_sound s(default_device->play_device(audio::device_config{format, length_to_sample_count(format, std::chrono::milliseconds(200))}));
	s.run(data);
	s.wait();
}

void play_sound_on_default_device(std::string file) {
	audio_data pcm;
	pcm.load(file);
	play_sound_on_default_device(pcm.format(), pcm.data());
}

}

