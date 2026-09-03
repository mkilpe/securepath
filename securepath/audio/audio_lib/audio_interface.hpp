// SPDX-License-Identifier: MIT

#pragma once

#include "audio_device.hpp"

namespace securepath::audio {

class audio_interface {
public:
	virtual ~audio_interface() {}
	virtual std::string name() const = 0;
	virtual adinfos enumerate_devices(audio_device_type) const = 0;
	virtual audio_play_device_ptr play_device(device_config const& config, audio_device_info_ptr = nullptr) const = 0;
	virtual audio_capture_device_ptr capture_device(device_config const& config, audio_device_info_ptr = nullptr) const = 0;
};

typedef std::shared_ptr<audio_interface> audio_interface_ptr;

audio_interface_ptr create_default_audio_interface();

}

