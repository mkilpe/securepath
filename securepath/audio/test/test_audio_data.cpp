// SPDX-License-Identifier: MIT

#include <securepath/audio/util/audio_data.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <cmath>
#include <cstring>
#include <filesystem>
#include <limits>
#include <vector>

namespace securepath::audio::test {

namespace {

audio_format fmt(sample_type t, std::uint32_t channels, std::uint32_t bits, std::uint32_t rate) {
	return audio_format{t, channels, bits, rate, std::endian::little};
}

audio_format float_mono(std::uint32_t rate) {
	return fmt(float_t, 1, 32, rate);
}

octet_vector from_samples(std::initializer_list<std::int16_t> values) {
	octet_vector out(values.size()*2);
	std::uint8_t* p = out.data();
	for(std::int16_t v : values) {
		std::memcpy(p, &v, 2);
		p += 2;
	}
	return out;
}

std::int16_t sample_at(octet_vector const& data, std::size_t index) {
	std::int16_t v = 0;
	std::memcpy(&v, data.data() + index*2, 2);
	return v;
}

octet_vector to_bytes(std::vector<float> const& v) {
	octet_vector out(v.size() * sizeof(float));
	std::memcpy(out.data(), v.data(), out.size());
	return out;
}

std::vector<float> to_floats(octet_vector const& v) {
	std::vector<float> out(v.size() / sizeof(float));
	std::memcpy(out.data(), v.data(), v.size());
	return out;
}

// values stay within [-1, 1]: write_sample clamps on encode
std::vector<float> ramp(std::size_t n) {
	std::vector<float> v(n);
	for(std::size_t i = 0; i != n; ++i) {
		v[i] = i / 256.0f;
	}
	return v;
}

// save under a temporary name, load the result back and remove the file
audio_data save_and_load(audio_data const& source, audio_format const& saved_format) {
	auto const path = std::filesystem::path("test_audio_data_convert.wav");
	audio_data copy = source;
	copy.save(path.string(), saved_format);
	audio_data loaded;
	loaded.load(path.string());
	std::filesystem::remove(path);
	return loaded;
}

}

TEST_CASE("resample duplicates mono to stereo", "[audio]") {
	audio_data d(fmt(short_t, 1, 16, 24000), from_samples({1000, -2000}));
	d.resample(fmt(short_t, 2, 16, 24000));
	auto out = d.data();
	REQUIRE(out.size() == 8);
	CHECK(sample_at(out, 0) == 1000);
	CHECK(sample_at(out, 1) == 1000);
	CHECK(sample_at(out, 2) == -2000);
	CHECK(sample_at(out, 3) == -2000);
}

TEST_CASE("resample mixes stereo to mono", "[audio]") {
	audio_data d(fmt(short_t, 2, 16, 24000), from_samples({1000, 3000, -1000, -3000}));
	d.resample(fmt(short_t, 1, 16, 24000));
	auto out = d.data();
	REQUIRE(out.size() == 4);
	CHECK(sample_at(out, 0) == 2000);
	CHECK(sample_at(out, 1) == -2000);
}

TEST_CASE("resample converts the sample rate", "[audio]") {
	audio_data d(fmt(short_t, 1, 16, 24000), from_samples({0, 1000, 2000, 3000}));
	d.resample(fmt(short_t, 1, 16, 48000));
	auto out = d.data();
	REQUIRE(out.size() == 16); // 4 frames at 24k -> 8 frames at 48k
	CHECK(sample_at(out, 0) == 0);
	CHECK(sample_at(out, 1) == 500); // linear interpolation between 0 and 1000
	CHECK(sample_at(out, 2) == 1000);
	CHECK(d.format().samples_per_second == 48000);
}

TEST_CASE("resample upsamples floats with linear interpolation", "[audio]") {
	audio_data d{float_mono(22050), to_bytes(ramp(100))};
	d.resample(float_mono(44100));

	CHECK(d.format().samples_per_second == 44100);
	auto out = to_floats(d.data());
	REQUIRE(out.size() == 200);
	CHECK(out[0] == Catch::Approx(0.0f));
	CHECK(out[1] == Catch::Approx(0.5f / 256));
	CHECK(out[2] == Catch::Approx(1.0f / 256));
	CHECK(out[199] == Catch::Approx(99.0f / 256));
}

TEST_CASE("resample downsamples to matching duration", "[audio]") {
	audio_data d{float_mono(44100), to_bytes(ramp(200))};
	d.resample(float_mono(22050));

	auto out = to_floats(d.data());
	REQUIRE(out.size() == 100);
	CHECK(out[1] == Catch::Approx(2.0f / 256));
	CHECK(out[99] == Catch::Approx(198.0f / 256));
}

TEST_CASE("resample preserves duration for non-integer ratios", "[audio]") {
	std::size_t const src_frames = 1000;
	audio_data d{float_mono(22050), to_bytes(std::vector<float>(src_frames, 0.25f))};
	d.resample(float_mono(48000));

	auto out = to_floats(d.data());
	double const expected = double(src_frames) * 48000 / 22050;
	CHECK(std::abs(double(out.size()) - expected) <= 1.0);
	for(float v : out) {
		REQUIRE(v == Catch::Approx(0.25f));
	}
}

TEST_CASE("resample without rate change keeps the frame count", "[audio]") {
	// stereo 16-bit, frames (L,R): (0,16384), (-16384,0)
	audio_data d{fmt(short_t, 2, 16, 44100), from_samples({0, 16384, -16384, 0})};
	d.resample(float_mono(44100));

	auto out = to_floats(d.data());
	REQUIRE(out.size() == 2);
	CHECK(out[0] == Catch::Approx(0.25f));  // (0 + 0.5) / 2
	CHECK(out[1] == Catch::Approx(-0.25f)); // (-0.5 + 0) / 2
}

TEST_CASE("resample converts short to float and back exactly", "[audio]") {
	// read divides by 32768 and write must multiply by the same scale
	// (rounding, not truncating), or every save/load cycle drifts
	auto const original = from_samples({-32768, -12345, -1000, -1, 0, 1, 1000, 12345, 32767});
	audio_data d(fmt(short_t, 1, 16, 24000), original);
	d.resample(fmt(float_t, 1, 32, 24000));
	CHECK(d.data().size() == original.size()*2);
	d.resample(fmt(short_t, 1, 16, 24000));
	CHECK(d.data() == original);
}

TEST_CASE("non-finite float samples convert to silence", "[audio]") {
	// NaN passes through std::clamp, and float to int conversion of NaN or
	// infinity is undefined behaviour
	std::vector<float> src{std::numeric_limits<float>::quiet_NaN(),
		std::numeric_limits<float>::infinity(),
		-std::numeric_limits<float>::infinity(), 0.5f};
	audio_data d{float_mono(44100), to_bytes(src)};
	d.resample(fmt(short_t, 1, 16, 44100));

	auto out = d.data();
	REQUIRE(out.size() == src.size()*2);
	CHECK(sample_at(out, 0) == 0);
	CHECK(sample_at(out, 1) == 0);
	CHECK(sample_at(out, 2) == 0);
	CHECK(sample_at(out, 3) == 16384);
}

TEST_CASE("resample rejects zero sample rates", "[audio]") {
	audio_data zero_src{float_mono(0), to_bytes(ramp(10))};
	CHECK_THROWS_AS(zero_src.resample(float_mono(44100)), invalid_format);

	audio_data zero_dst{float_mono(44100), to_bytes(ramp(10))};
	CHECK_THROWS_AS(zero_dst.resample(float_mono(0)), invalid_format);
}

TEST_CASE("audio_data saves and loads a wav file", "[audio]") {
	auto const path = std::filesystem::path("test_audio_data.wav");
	auto const format = fmt(short_t, 2, 16, 48000);
	auto const payload = from_samples({100, 200, -100, -200});
	{
		audio_data d(format, payload);
		d.save(path.string());
	}
	audio_data loaded;
	loaded.load(path.string());
	std::filesystem::remove(path);
	CHECK(loaded.format() == format);
	CHECK(loaded.data() == payload);
}

TEST_CASE("audio_data save converts 16-bit PCM to float", "[audio]") {
	audio_data source(fmt(short_t, 1, 16, 44100), from_samples({0, 16384, -16384}));
	audio_data loaded = save_and_load(source, float_mono(44100));

	CHECK(loaded.format().type == float_t);
	CHECK(loaded.format().bits_per_sample == 32);
	auto out = to_floats(loaded.data());
	REQUIRE(out.size() == 3);
	CHECK(out[0] == Catch::Approx(0.0f).margin(0.001f));
	CHECK(out[1] == Catch::Approx(0.5f).margin(0.001f));
	CHECK(out[2] == Catch::Approx(-0.5f).margin(0.001f));
}

TEST_CASE("audio_data save converts float to 16-bit PCM", "[audio]") {
	audio_data source(float_mono(44100), to_bytes({0.0f, 0.5f, -0.5f}));
	audio_data loaded = save_and_load(source, fmt(short_t, 1, 16, 44100));

	CHECK(loaded.format().type == short_t);
	CHECK(loaded.format().bits_per_sample == 16);
	auto const out = loaded.data();
	REQUIRE(out.size() == 6);
	CHECK(sample_at(out, 0) == 0);
	CHECK(sample_at(out, 1) == Catch::Approx(16384).margin(1));
	CHECK(sample_at(out, 2) == Catch::Approx(-16384).margin(1));
}

TEST_CASE("load_file_to_buffer produces a filled buffer", "[audio]") {
	auto const path = std::filesystem::path("test_audio_buffer.wav");
	auto const format = fmt(short_t, 1, 16, 24000);
	{
		audio_data d(format, from_samples({1, 2, 3}));
		d.save(path.string());
	}
	auto buffer = load_file_to_buffer(path.string());
	std::filesystem::remove(path);
	CHECK(buffer.format() == format);
	CHECK(buffer.used_samples() == 3);
	CHECK(buffer.begin<std::int16_t>()[2] == 3);
}

}
