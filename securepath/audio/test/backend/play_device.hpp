// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/audio/audio_lib/audio_device.hpp>
#include <securepath/audio/audio_lib/audio_interface.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <cstdlib>
#include <exception>

namespace securepath::audio::test {

// The backend tests need a play device, which the build machines of this
// library do not have: without one a test skips. A CI that does provide
// audio sets SECUREPATH_AUDIO_TESTS_REQUIRE_DEVICE, and then a missing
// device is a failure rather than a silent skip.
inline bool device_required() {
	return std::getenv("SECUREPATH_AUDIO_TESTS_REQUIRE_DEVICE") != nullptr;
}

inline void report_missing_device(char const* what) {
	if(device_required()) {
		FAIL(what << " and SECUREPATH_AUDIO_TESTS_REQUIRE_DEVICE is set");
	}
	WARN(what << ", skipping");
}

// the default play device, or null when there is none (already reported)
inline audio_play_device_ptr open_play_device(device_config const& conf, audio_device_info_ptr info = nullptr) {
	audio_play_device_ptr dev;
	auto iface = create_default_audio_interface();
	if(iface) {
		try {
			dev = iface->play_device(conf, info);
		} catch(std::exception const& e) {
			INFO("play_device: " << e.what());
		}
	}
	if(!dev) {
		report_missing_device("no play device available");
	}
	return dev;
}

}
