// SPDX-License-Identifier: MIT

#include <securepath/audio/audio_lib/audio_buffer.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <initializer_list>
#include <stdexcept>

namespace securepath::audio::test {

namespace {

audio_format short_mono() {
	return audio_format{short_t, 1, 16, 24000, std::endian::little};
}

audio_format float_mono() {
	return audio_format{float_t, 1, 32, 24000, std::endian::little};
}

audio_buffer make_buffer(std::initializer_list<std::int16_t> values, std::size_t capacity) {
	audio_buffer b(short_mono(), capacity);
	std::int16_t* p = b.begin<std::int16_t>();
	for(std::int16_t v : values) {
		*p++ = v;
	}
	b.set_used_samples(values.size());
	return b;
}

audio_buffer make_float_buffer(std::initializer_list<float> values) {
	audio_buffer b(float_mono(), values.size());
	float* p = b.begin<float>();
	for(float v : values) {
		*p++ = v;
	}
	b.set_used_samples(values.size());
	return b;
}

}

TEST_CASE("audio_buffer basic accounting", "[audio]") {
	audio_buffer b(short_mono(), 8);
	CHECK(b.samples() == 8);
	CHECK(b.size() == 16);
	CHECK(b.empty());
	CHECK(b.free_samples() == 8);

	b.add_silence_samples(4);
	CHECK(b.used_samples() == 4);
	CHECK(!b.empty());
	CHECK(!b.full());
	for(std::size_t i = 0; i != 4; ++i) {
		CHECK(b.begin<std::int16_t>()[i] == 0);
	}
}

TEST_CASE("audio_buffer from raw data", "[audio]") {
	octet_vector data{0x01, 0x02, 0x03, 0x04};
	audio_buffer b(short_mono(), data);
	CHECK(b.samples() == 2);
	CHECK(b.used_samples() == 2);
	CHECK(b.begin<std::int16_t>()[0] == 0x0201);
	CHECK(b.begin<std::int16_t>()[1] == 0x0403);
}

TEST_CASE("audio_buffer rejects inconsistent formats", "[audio]") {
	audio_format f = short_mono();
	f.bits_per_sample = 8; // disagrees with short_t storage
	CHECK_THROWS_AS(audio_buffer(f, 4), std::invalid_argument);

	// the storage type and bits_per_sample must agree in every combination,
	// or the size arithmetic desyncs from the data
	audio_format wide_char{char_t, 1, 32, 24000, std::endian::little};
	CHECK_THROWS_AS(audio_buffer(wide_char, 16), std::invalid_argument);
	audio_format narrow_float{float_t, 1, 16, 24000, std::endian::little};
	CHECK_THROWS_AS(audio_buffer(narrow_float, 16), std::invalid_argument);

	// data size not a multiple of the sample size: rounding the sample count
	// down and then copying the full data would write past the end
	octet_vector odd{0x01, 0x02, 0x03};
	CHECK_THROWS_AS(audio_buffer(short_mono(), odd), std::invalid_argument);
	octet_vector five{1, 2, 3, 4, 5};
	CHECK_THROWS_AS(audio_buffer(float_mono(), five), std::invalid_argument);
}

TEST_CASE("audio_buffer consume moves the remaining samples", "[audio]") {
	audio_buffer b = make_buffer({1, 2, 3, 4}, 4);
	b.consume_samples(2);
	CHECK(b.used_samples() == 2);
	CHECK(b.begin<std::int16_t>()[0] == 3);
	CHECK(b.begin<std::int16_t>()[1] == 4);
	b.consume_samples(2);
	CHECK(b.empty());
}

TEST_CASE("audio_buffer mix and scale", "[audio]") {
	audio_buffer a = make_buffer({1000, -1000, 30000, 100}, 4);
	audio_buffer b = make_buffer({500, -500, 30000, -100}, 4);

	a.mix(0, b, 0, 4, 1.0);
	CHECK(a.begin<std::int16_t>()[0] == 1500);
	CHECK(a.begin<std::int16_t>()[1] == -1500);
	CHECK(a.begin<std::int16_t>()[2] == 32767); // clamped
	CHECK(a.begin<std::int16_t>()[3] == 0);

	a.scale(0, 2, 0.5);
	CHECK(a.begin<std::int16_t>()[0] == 750);
	CHECK(a.begin<std::int16_t>()[1] == -750);
}

TEST_CASE("audio_buffer int16 mix and scale clamp at both ends", "[audio]") {
	audio_buffer a = make_buffer({30000, -30000}, 2);
	audio_buffer b = make_buffer({30000, -30000}, 2);
	a.mix(0, b, 0, 2, 1.0);
	CHECK(a.begin<std::int16_t>()[0] == 32767);
	CHECK(a.begin<std::int16_t>()[1] == -32768);

	audio_buffer c = make_buffer({30000}, 1);
	c.scale(0, 1, 2.0);
	CHECK(c.begin<std::int16_t>()[0] == 32767);
}

TEST_CASE("audio_buffer float mix adds samples", "[audio]") {
	// an integer-based mix truncates float samples to whole numbers and
	// clamps negative values away
	audio_buffer a = make_float_buffer({0.5f, -0.5f, 0.25f});
	audio_buffer b = make_float_buffer({0.25f, -0.25f, -0.75f});

	a.mix(0, b, 0, 3, 1.0);
	float const* p = a.begin<float>();
	CHECK(p[0] == Catch::Approx(0.75f));
	CHECK(p[1] == Catch::Approx(-0.75f));
	CHECK(p[2] == Catch::Approx(-0.5f));
}

TEST_CASE("audio_buffer float scale keeps negative values", "[audio]") {
	audio_buffer a = make_float_buffer({0.5f, -0.5f});
	a.scale(0, 2, 0.5);
	float const* p = a.begin<float>();
	CHECK(p[0] == Catch::Approx(0.25f));
	CHECK(p[1] == Catch::Approx(-0.25f));
}

TEST_CASE("audio_buffer rejects mixing different sample types", "[audio]") {
	audio_buffer a = make_buffer({1, 2}, 2);
	audio_format f{float_t, 1, 32, 24000, std::endian::little};
	audio_buffer b(f, 2);
	b.add_silence_samples(2);
	CHECK_THROWS_AS(a.mix(0, b, 0, 2, 1.0), std::invalid_argument);
}

TEST_CASE("audio_buffer copy is independent", "[audio]") {
	audio_buffer a = make_buffer({7, 8, 9}, 3);
	audio_buffer b = a.copy();
	CHECK(b.used_samples() == 3);
	CHECK(b.format() == a.format());
	b.begin<std::int16_t>()[0] = 42;
	CHECK(a.begin<std::int16_t>()[0] == 7);
	CHECK(b.begin<std::int16_t>()[0] == 42);
}

}
