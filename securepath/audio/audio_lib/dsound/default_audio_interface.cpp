// SPDX-License-Identifier: MIT


#include "../audio_interface.hpp"
#include "dsound.hpp"

namespace securepath::audio {

audio_interface_ptr create_default_audio_interface()
{
	return std::make_shared<dsound_audio_interface>();
}

}
