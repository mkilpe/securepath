// SPDX-License-Identifier: MIT

#include <securepath/audio/util/detail/wav.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <cstdint>
#include <optional>
#include <sstream>
#include <string_view>

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

riff::riff_fmt_data make_fmt(std::uint16_t audio_format, std::uint16_t channels,
	std::uint32_t sample_rate, std::uint16_t bits) {
	riff::riff_fmt_data f;
	f.audio_format = audio_format;
	f.channels = channels;
	f.sample_rate = sample_rate;
	f.bits_per_sample = bits;
	f.byte_rate = sample_rate * channels * bits / 8;
	f.block_align = static_cast<std::uint16_t>(channels * bits / 8);
	return f;
}

riff::riff_fmt_data valid_fmt() {
	return make_fmt(1, 2, 48000, 16); // PCM, stereo
}

// -- chunk-level byte streams, built through the shared riff serialisers so
//    the encoding is portable and defined in one place --

template<typename Writer>
void append_written(octet_vector& v, Writer const& w, std::size_t size) {
	std::size_t const old = v.size();
	v.resize(old + size);
	w.write(v.data() + old, size);
}

void put_ascii(octet_vector& v, std::string_view s) {
	v.insert(v.end(), s.begin(), s.end());
}

void put_chunk(octet_vector& v, char const (&id)[5], octet_vector const& payload,
	std::optional<std::uint32_t> declared_size = std::nullopt) {
	riff::chunk_header h{
		{std::uint8_t(id[0]), std::uint8_t(id[1]), std::uint8_t(id[2]), std::uint8_t(id[3])},
		declared_size.value_or(static_cast<std::uint32_t>(payload.size()))};
	append_written(v, h, riff::chunk_header::size);
	v.insert(v.end(), payload.begin(), payload.end());
}

octet_vector fmt_payload_pcm8_mono() {
	octet_vector p;
	append_written(p, make_fmt(1, 1, 44100, 8), riff::riff_fmt_data::size);
	return p;
}

// chunks = concatenated chunk bytes following the WAVE tag
octet_vector raw_wav(octet_vector const& chunks) {
	octet_vector v;
	append_written(v, riff::riff_header{static_cast<std::uint32_t>(chunks.size())}, riff::riff_header::size);
	v.insert(v.end(), chunks.begin(), chunks.end());
	return v;
}

void load_raw(octet_vector const& bytes, octet_vector& out) {
	std::istringstream in(std::string(bytes.begin(), bytes.end()), std::ios_base::binary);
	wav w(out);
	w.load(in);
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

TEST_CASE("validate_wav_format accepts the supported formats", "[audio]") {
	CHECK_NOTHROW(validate_wav_format(make_fmt(1, 1, 44100, 8), 16));
	CHECK_NOTHROW(validate_wav_format(make_fmt(1, 2, 44100, 16), 16));
	CHECK_NOTHROW(validate_wav_format(make_fmt(1, 1, 48000, 24), 15));
	CHECK_NOTHROW(validate_wav_format(make_fmt(3, 2, 44100, 32), 16));
}

TEST_CASE("validate_wav_format enforces decoder limits", "[audio]") {
	CHECK_NOTHROW(validate_wav_format(valid_fmt(), 8));

	auto f = valid_fmt();
	f.channels = 0; // would divide by zero in resample
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.channels = max_supported_channels + 1;
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.sample_rate = 0; // would divide by zero in timing conversions
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.bits_per_sample = 12;
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	// float decode always reads 4 bytes: anything narrower over-reads the heap
	CHECK_THROWS_AS(validate_wav_format(make_fmt(3, 1, 44100, 8), 8), invalid_format);
	CHECK_THROWS_AS(validate_wav_format(make_fmt(3, 1, 44100, 16), 16), invalid_format);

	// 32-bit integer PCM has no decoder and would be read as noise
	CHECK_THROWS_AS(validate_wav_format(make_fmt(1, 1, 44100, 32), 16), invalid_format);

	f = valid_fmt();
	CHECK_THROWS_AS(validate_wav_format(f, 7), invalid_format); // not frame aligned

	f = valid_fmt();
	f.audio_format = 2; // ADPCM: unsupported
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);

	f = valid_fmt();
	f.audio_format = 0xFFFE; // WAVE_FORMAT_EXTENSIBLE: unsupported
	CHECK_THROWS_AS(validate_wav_format(f, 8), invalid_format);
}

TEST_CASE("wav rejects a huge declared data chunk without allocating it", "[audio]") {
	// a 4 GB declared size in a tiny file must throw, not allocate
	octet_vector chunks;
	put_chunk(chunks, "fmt ", fmt_payload_pcm8_mono());
	put_chunk(chunks, "data", {1, 2, 3, 4}, 0xF0000000u);

	octet_vector out;
	CHECK_THROWS_AS(load_raw(raw_wav(chunks), out), invalid_format);
}

TEST_CASE("wav skips odd-sized chunks with their pad byte", "[audio]") {
	// an odd LIST chunk is padded to word alignment; the parser must skip
	// the pad or every following chunk header is misread
	octet_vector chunks;
	put_chunk(chunks, "LIST", {'I', 'N', 'F'});
	chunks.push_back(0); // pad byte
	put_chunk(chunks, "fmt ", fmt_payload_pcm8_mono());
	put_chunk(chunks, "data", {10, 20, 30, 40});

	octet_vector out;
	CHECK_NOTHROW(load_raw(raw_wav(chunks), out));
	CHECK(out == octet_vector{10, 20, 30, 40});
}

TEST_CASE("wav truncated inputs throw invalid_format", "[audio]") {
	octet_vector out;

	// cut off inside the RIFF header
	octet_vector header_only{'R', 'I', 'F', 'F', 0, 0};
	CHECK_THROWS_AS(load_raw(header_only, out), invalid_format);

	// fmt chunk declaring fewer bytes than the format struct needs
	{
		octet_vector chunks;
		put_chunk(chunks, "fmt ", {1, 0, 1, 0, 0, 0}, std::nullopt);
		put_chunk(chunks, "data", {1, 2});
		CHECK_THROWS_AS(load_raw(raw_wav(chunks), out), invalid_format);
	}

	// file ends in the middle of a chunk header
	{
		octet_vector chunks;
		put_chunk(chunks, "fmt ", fmt_payload_pcm8_mono());
		put_chunk(chunks, "data", {1, 2, 3, 4});
		put_ascii(chunks, "LI"); // partial next header
		CHECK_THROWS_AS(load_raw(raw_wav(chunks), out), invalid_format);
	}

	// data chunk declaring more bytes than the file has
	{
		octet_vector chunks;
		put_chunk(chunks, "fmt ", fmt_payload_pcm8_mono());
		put_chunk(chunks, "data", {1, 2, 3, 4}, 400);
		CHECK_THROWS_AS(load_raw(raw_wav(chunks), out), invalid_format);
	}
}

}
