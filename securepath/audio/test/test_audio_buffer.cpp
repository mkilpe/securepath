// SPDX-License-Identifier: MIT

#include <securepath/audio/audio_lib/audio_buffer.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <stdexcept>

namespace securepath::audio::test {

namespace {

audio_format short_mono() {
	return audio_format{short_t, 1, 16, 24000, std::endian::little};
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

	octet_vector odd{0x01, 0x02, 0x03};
	CHECK_THROWS_AS(audio_buffer(short_mono(), odd), std::invalid_argument);
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
