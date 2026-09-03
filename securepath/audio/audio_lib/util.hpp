// SPDX-License-Identifier: MIT

#pragma once

#include "audio_buffer.hpp"
#include <chrono>
#include <ostream>

namespace securepath::audio {

using length_type =	std::chrono::milliseconds;
using time_point = length_type;

std::size_t octets_to_sample_count(audio_format const&, std::size_t octets);
std::size_t length_to_sample_count(audio_format const&, length_type);
std::size_t samples_to_octet_count(audio_format const&, std::size_t samples);
std::size_t length_to_byte_count(audio_format const&, length_type);

length_type multiple_of_samples_length(length_type size, length_type samples_size);
length_type audio_buffer_to_length(audio_buffer const&);
length_type samples_to_length(audio_format const&, std::size_t samples);

double octets_to_duration(audio_format const&, std::size_t octets); //returns length in seconds
double samples_to_duration(audio_format const&, std::size_t samples); //returns length in seconds

//adjust volume by given value in dBs if the absolute of sample value is bigger than noise threshold per cents from the max value
void adjust_volume(audio_buffer&, double adjust, double noise_threshold);

}

