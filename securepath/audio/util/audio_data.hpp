// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/types.hpp>
#include <securepath/audio/audio_lib/audio_buffer.hpp>
#include <securepath/audio/audio_lib/audio_format.hpp>

#include <stdexcept>
#include <string>
#include <iosfwd>

namespace securepath::audio {

struct invalid_format : std::runtime_error { using std::runtime_error::runtime_error; };

class audio_data {
public:
	enum file_format { auto_format = 0, wav = 1, default_format = wav }; //only supported format for now

	audio_data() = default;
	audio_data(audio::audio_format format, octet_vector data);
	audio_data(audio::audio_buffer const& buffer);

	void load(std::string const& file, file_format = auto_format);
	void load(std::string const& file, audio::audio_format format, file_format = auto_format);
	void save(std::string const& file, file_format = auto_format);
	void save(std::string const& file, audio::audio_format const& format, file_format = auto_format);

	// Convert to the target format: sample type, channel remap and sample-rate
	// conversion (linear interpolation).
	void resample(audio::audio_format const& target);

	audio::audio_format format() const;
	octet_vector data() const; //interlaced data for multiple channels
private:
	audio::audio_format format_;
	octet_vector data_;
};

audio::audio_buffer load_file_to_buffer(std::string const& file, audio_data::file_format = audio_data::auto_format);

}

