// SPDX-License-Identifier: MIT

#include <securepath/audio/util/audio_data.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <cstring>
#include <filesystem>

namespace securepath::audio::test {

namespace {

audio_format fmt(sample_type t, std::uint32_t channels, std::uint32_t bits, std::uint32_t rate) {
	return audio_format{t, channels, bits, rate, std::endian::little};
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

TEST_CASE("resample converts short to float and back exactly", "[audio]") {
	auto const original = from_samples({-32768, -1000, 0, 1000, 32767});
	audio_data d(fmt(short_t, 1, 16, 24000), original);
	d.resample(fmt(float_t, 1, 32, 24000));
	CHECK(d.data().size() == original.size()*2);
	d.resample(fmt(short_t, 1, 16, 24000));
	CHECK(d.data() == original);
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
