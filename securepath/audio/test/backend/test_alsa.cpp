// SPDX-License-Identifier: MIT

// ALSA backend tests. The null PCM plugin is selected via ALSA_CONFIG_PATH,
// so no audio hardware is needed.

#include "play_device.hpp"

#include <securepath/audio/audio_lib/audio_buffer.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace securepath::audio::test {

namespace {

// must take effect before the first ALSA call in the process
struct null_alsa_config {
	null_alsa_config() {
		auto conf = std::filesystem::temp_directory_path() / "securepath_test_asound.conf";
		std::ofstream(conf.string()) << "pcm.!default {\n\ttype null\n}\n";
		::setenv("ALSA_CONFIG_PATH", conf.string().c_str(), 1);
	}
};

audio_play_device_ptr open_null_device(device_config const& conf) {
	static null_alsa_config config_guard;
	return open_play_device(conf);
}

void check_full_buffer_write(std::uint32_t channels) {
	device_config conf{{float_t, channels, 32, 44100}, 8820};
	auto dev = open_null_device(conf);
	if(!dev) {
		return;
	}
	auto real = dev->config();
	REQUIRE(real.format.channels == channels);
	// buffer/period sizes are reported in samples, so whole frames only
	CHECK(real.buffer_size % channels == 0);
	CHECK(real.period_size % channels == 0);

	audio_buffer buf(real.format, real.buffer_size);
	float* p = buf.begin<float>();
	for(std::size_t i = 0; i != real.buffer_size; ++i) {
		p[i] = 0.0f;
	}
	buf.set_used_samples(static_cast<unsigned>(real.buffer_size));

	dev->start();
	auto written = dev->write(buf);
	dev->stop();

	// write() reports samples; a frames/samples mix-up halves or doubles this
	CHECK(written == real.buffer_size);
	CHECK(buf.used_samples() == 0);
}

}

TEST_CASE("alsa stereo write consumes whole buffers", "[audio][alsa]") {
	check_full_buffer_write(2);
}

TEST_CASE("alsa mono write consumes whole buffers", "[audio][alsa]") {
	check_full_buffer_write(1);
}

}
