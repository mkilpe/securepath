// SPDX-License-Identifier: MIT

#pragma once

#include "../audio_interface.hpp"

namespace securepath::audio {

class dsound_audio_interface : public audio_interface {
public:

	virtual std::string name() const;
	virtual adinfos enumerate_devices(audio_device_type) const;
	virtual audio_play_device_ptr play_device(device_config const& config, audio_device_info_ptr = nullptr) const;
	virtual audio_capture_device_ptr capture_device(device_config const& config, audio_device_info_ptr = nullptr) const;
};

}

