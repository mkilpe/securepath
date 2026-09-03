// SPDX-License-Identifier: MIT

#include <securepath/audio/audio_lib/util.hpp>
#include <securepath/test_frame/test_suite.hpp>

namespace securepath::audio::test {

namespace {

audio_format fmt(std::uint32_t channels, std::uint32_t rate) {
	return audio_format{short_t, channels, 16, rate, std::endian::little};
}

}

TEST_CASE("sample count conversions", "[audio]") {
	audio_format f = fmt(2, 48000);
	CHECK(octets_to_sample_count(f, 4) == 2);
	CHECK(samples_to_octet_count(f, 2) == 4);
	CHECK(length_to_sample_count(f, length_type{100}) == 9600);
	CHECK(samples_to_length(f, 9600) == length_type{100});
	CHECK(length_to_byte_count(f, length_type{100}) == 19200);
	CHECK(multiple_of_samples_length(length_type{1050}, length_type{100}) == length_type{1000});
}

TEST_CASE("duration conversions", "[audio]") {
	audio_format f = fmt(1, 24000);
	CHECK(samples_to_duration(f, 24000) == 1.0);
	CHECK(octets_to_duration(f, 48000) == 1.0);
}

TEST_CASE("adjust_volume scales samples above the noise threshold", "[audio]") {
	audio_buffer b(fmt(1, 24000), 2);
	b.begin<std::int16_t>()[0] = 100;    // below threshold: untouched
	b.begin<std::int16_t>()[1] = 10000;  // above: scaled
	b.set_used_samples(2);

	// ~ +6dB is a factor of about two; threshold at 10% of full scale
	adjust_volume(b, 6.0206, 0.1);
	CHECK(b.begin<std::int16_t>()[0] == 100);
	CHECK(b.begin<std::int16_t>()[1] == 20000);
}

TEST_CASE("adjust_volume clamps to the sample range", "[audio]") {
	audio_buffer b(fmt(1, 24000), 1);
	b.begin<std::int16_t>()[0] = 30000;
	b.set_used_samples(1);
	adjust_volume(b, 6.0206, 0.1);
	CHECK(b.begin<std::int16_t>()[0] == 32767);
}

}
