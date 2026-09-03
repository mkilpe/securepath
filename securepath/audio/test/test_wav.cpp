// SPDX-License-Identifier: MIT

#include <securepath/audio/util/detail/wav.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <sstream>

namespace securepath::audio::test {

namespace {

octet_vector round_trip(octet_vector const& data, audio_format const& fmt, audio_format& loaded_fmt) {
	std::ostringstream out;
	{
		octet_vector d = data;
		wav w(d);
		w.save(out, fmt);
	}
	std::istringstream in(out.str());
	octet_vector loaded;
	wav r(loaded);
	r.load(in);
	loaded_fmt = r.format();
	return loaded;
}

riff::riff_fmt_data valid_fmt() {
	riff::riff_fmt_data f;
	f.audio_format = 1; // PCM
	f.channels = 2;
	f.sample_rate = 48000;
	f.byte_rate = 48000*2*2;
	f.block_align = 4;
	f.bits_per_sample = 16;
	return f;
}

}

TEST_CASE("wav round trip for 16 bit PCM", "[audio]") {
	audio_format fmt{short_t, 1, 16, 24000, std::endian::little};
	octet_vector data{0x01, 0x02, 0x03, 0x04};
	audio_format loaded_fmt;
	CHECK(round_trip(data, fmt, loaded_fmt) == data);
	CHECK(loaded_fmt == fmt);
}

TEST_CASE("wav round trip for float stereo", "[audio]") {
	audio_format fmt{float_t, 2, 32, 48000, std::endian::little};
	octet_vector data(16, 0x3f);
	audio_format loaded_fmt;
	CHECK(round_trip(data, fmt, loaded_fmt) == data);
	CHECK(loaded_fmt == fmt);
}

TEST_CASE("wav save rejects unsupported formats", "[audio]") {
	octet_vector data{0x01, 0x02};
	std::ostringstream out;
	wav w(data);
	audio_format big{short_t, 1, 16, 24000, std::endian::big};
	CHECK_THROWS_AS(w.save(out, big), invalid_format);
	audio_format c{char_t, 1, 8, 24000, std::endian::little};
	CHECK_THROWS_AS(w.save(out, c), invalid_format);
}

TEST_CASE("wav load rejects malformed input", "[audio]") {
	octet_vector data;
	{
		std::istringstream in("RIF");
		wav w(data);
		CHECK_THROWS_AS(w.load(in), invalid_format);
	}
	{
		std::istringstream in("XXXXxxxxWAVEyyyy");
		wav w(data);
		CHECK_THROWS_AS(w.load(in), invalid_format);
	}
}

TEST_CASE("validate_wav_format enforces decoder limits", "[audio]") {
	CHECK_NOTHROW(validate_wav_format(valid_fmt(), 8));

	auto f = valid_fmt();
	f.channels = 0;
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.channels = max_supported_channels + 1;
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.bits_per_sample = 12;
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.audio_format = 3; // float must be 32 bit
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	CHECK_THROWS_AS(validate_wav_format(f, 7), invalid_format); // not frame aligned

	f = valid_fmt();
	f.audio_format = 2; // ADPCM: unsupported
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);
}

}
