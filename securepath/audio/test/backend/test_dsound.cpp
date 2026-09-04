// SPDX-License-Identifier: MIT

// DirectSound backend tests. Runnable on a real machine or under Wine with
// winepulse on a PulseAudio/PipeWire server (a null sink is enough: no
// hardware needed, but audio must be consumed at the sample rate for the
// timing cases; ALSA's null plugin consumes instantly and fails them).

#include "play_device.hpp"

#include <securepath/audio/audio_lib/audio_buffer.hpp>
#include <securepath/audio/audio_lib/audio_device_modes.hpp>

#include <chrono>
#include <thread>

namespace securepath::audio::test {

namespace {

using namespace std::chrono;

// 0.2 s mono float buffer at 44100
device_config dsound_test_config() {
	return {{float_t, 1, 32, 44100}, 8820};
}

audio_buffer silence_buffer(device_config const& conf, std::size_t samples) {
	audio_buffer b(conf.format, conf.buffer_size);
	float* p = b.begin<float>();
	for(std::size_t i = 0; i != samples; ++i) {
		p[i] = 0.0f;
	}
	b.set_used_samples(static_cast<unsigned>(samples));
	return b;
}

}

TEST_CASE("dsound default play device opens with notification support", "[audio][dsound]") {
	auto dev = open_play_device(dsound_test_config());
	if(!dev) {
		return;
	}
	CHECK((dev->supported_modes() & audio_device_mode::notifications) != 0);
	CHECK(dev->buffer_size() == 8820);
}

TEST_CASE("dsound every enumerated play device opens (including primary)", "[audio][dsound]") {
	// a driverless environment (CI) still enumerates the primary device but
	// cannot open anything; require a usable default device first
	if(!open_play_device(dsound_test_config())) {
		return;
	}
	auto iface = create_default_audio_interface();
	REQUIRE(iface);
	auto infos = iface->enumerate_devices(audio_device_t::play);
	if(infos.empty()) {
		report_missing_device("no play devices enumerated");
		return;
	}
	for(auto const& info : infos) {
		INFO("device: " << info->description());
		// the primary device is enumerated with a null guid, which must open
		// like any other
		auto dev = iface->play_device(dsound_test_config(), info);
		CHECK(dev);
	}
}

TEST_CASE("dsound wait() blocks until audio is consumed", "[audio][dsound]") {
	auto dev = open_play_device(dsound_test_config());
	if(!dev) {
		return;
	}
	auto conf = dev->config();

	std::size_t const period = 2205; // 50 ms; buffer = 4 periods
	dev->set_mode(notification_mode{period});

	auto buf = silence_buffer(conf, conf.buffer_size);
	dev->write(buf);
	dev->start();

	auto t0 = steady_clock::now();
	int woken = 0;
	for(int i = 0; i != 8; ++i) {
		if(dev->wait()) {
			++woken;
		}
	}
	auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t0).count();
	dev->stop();

	INFO("8 waits took " << elapsed << " ms, " << woken << " woken");
	// 8 periods of 50 ms = 400 ms of real playback; a wait that returns
	// immediately turns the caller into a busy loop
	CHECK(elapsed >= 250);
	CHECK(elapsed <= 2000);
	CHECK(woken >= 6);
}

TEST_CASE("dsound stop(drain) returns within bounded time", "[audio][dsound]") {
	auto dev = open_play_device(dsound_test_config());
	if(!dev) {
		return;
	}
	auto conf = dev->config();

	auto buf = silence_buffer(conf, conf.buffer_size / 2);
	dev->write(buf);
	dev->start();

	auto t0 = steady_clock::now();
	dev->stop(stop_type::drain);
	auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t0).count();

	INFO("drain took " << elapsed << " ms");
	// at most the 100 ms of written audio remains; allow generous scheduling slack
	CHECK(elapsed <= 1000);
}

TEST_CASE("dsound stereo device counts in samples, not frames", "[audio][dsound]") {
	// 0.4 s stereo float buffer: 35280 samples = 17640 frames
	device_config conf{{float_t, 2, 32, 44100}, 35280};
	auto dev = open_play_device(conf);
	if(!dev) {
		return;
	}
	CHECK(dev->buffer_size() == 35280);

	auto buf = silence_buffer(dev->config(), dev->config().buffer_size);
	auto written = dev->write(buf);
	// the pre-start fill takes (nearly) the whole buffer, counted in samples;
	// counting frames would report half
	CHECK(written > 35280 / 2);

	dev->start();
	std::this_thread::sleep_for(milliseconds(100));
	auto consumed = dev->avail();
	dev->stop();

	INFO("consumed " << consumed << " samples in ~100 ms");
	// ~100 ms of stereo at 44100 = ~8820 samples; counting frames gives half,
	// and a ring sized in frames instead of samples skews it further
	CHECK(consumed > 6600);
	CHECK(consumed < 14000);
}

TEST_CASE("dsound stop(drain) after a full pre-start fill plays the audio out", "[audio][dsound]") {
	auto dev = open_play_device(dsound_test_config()); // 0.2 s mono buffer
	if(!dev) {
		return;
	}
	auto conf = dev->config();

	// fill the whole ring before starting, so the write position lands exactly
	// on the play cursor: the empty and full states look identical there
	auto buf = silence_buffer(conf, conf.buffer_size);
	dev->write(buf);
	dev->start();

	auto t0 = steady_clock::now();
	dev->stop(stop_type::drain);
	auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t0).count();

	INFO("drain took " << elapsed << " ms");
	// ~200 ms of audio was queued; a drain that mistakes full for empty
	// zeroes it and returns immediately
	CHECK(elapsed >= 120);
	CHECK(elapsed <= 1000);
}

TEST_CASE("dsound play cursor advances in real time", "[audio][dsound]") {
	auto dev = open_play_device(dsound_test_config());
	if(!dev) {
		return;
	}
	auto conf = dev->config();

	auto buf = silence_buffer(conf, conf.buffer_size);
	dev->write(buf);
	dev->start();
	std::this_thread::sleep_for(milliseconds(100));
	auto consumed = dev->avail();
	dev->stop();

	INFO("consumed " << consumed << " samples in ~100 ms");
	// ~4410 samples expected; require it moved meaningfully and sanely
	CHECK(consumed > 1000);
	CHECK(consumed < 20000);
}

TEST_CASE("dsound wait() interrupted by stop() from another thread", "[audio][dsound]") {
	auto dev = open_play_device(dsound_test_config());
	if(!dev) {
		return;
	}
	dev->set_mode(notification_mode{2205});

	// not started: no notifications will fire, so wait() parks until stop()
	auto t0 = steady_clock::now();
	std::thread stopper{[&dev] {
		std::this_thread::sleep_for(milliseconds(100));
		dev->stop();
	}};
	bool woke_playing = dev->wait();
	auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t0).count();
	stopper.join();

	INFO("wait returned " << woke_playing << " after " << elapsed << " ms");
	CHECK(!woke_playing); // stopped, not playing
	CHECK(elapsed < 1000);
}

TEST_CASE("dsound capture set_notification computes points safely", "[audio][dsound]") {
	auto iface = create_default_audio_interface();
	REQUIRE(iface);
	try {
		auto dev = iface->capture_device(dsound_test_config());
		// the notification points derive from the buffer length, which must be
		// set before this call
		dev->set_mode(notification_mode{2205});
		SUCCEED("capture notification configured");
	} catch(std::exception const& e) {
		WARN("no capture device in this environment: " << e.what());
	}
}

}
