securepath_add_test(test_audio audio audio_util test_frame)

# The backend tests sit outside the glob: each one drives the platform's own
# backend through create_default_audio_interface(), so only the matching one
# is compiled in. They skip without a play device unless
# SECUREPATH_AUDIO_TESTS_REQUIRE_DEVICE is set (see backend/play_device.hpp).
if(WIN32)
    target_sources(test_audio PRIVATE backend/test_dsound.cpp)
elseif(SECUREPATH_HAVE_ALSA)
    target_sources(test_audio PRIVATE backend/test_alsa.cpp)
endif()
