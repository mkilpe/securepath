// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/audio/audio_lib/audio_device.hpp>
#include <securepath/util/types.hpp>

namespace securepath::audio {

class play_sound {
public:
	play_sound(audio::audio_play_device_ptr);

	void run(octet_vector const& data);

	//wait until the sound buffer is empty
	void wait();
private:
	audio::audio_play_device_ptr playback_;
};

void play_sound_on_default_device(audio::audio_format format, octet_vector const& data);
void play_sound_on_default_device(std::string file);

}