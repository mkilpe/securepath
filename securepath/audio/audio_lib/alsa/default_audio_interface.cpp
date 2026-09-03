// SPDX-License-Identifier: MIT


#include "../audio_interface.hpp"
#include "alsa.hpp"

namespace securepath::audio {

audio_interface_ptr create_default_audio_interface()
{
	return std::make_shared<alsa_audio_interface>();
}

}
