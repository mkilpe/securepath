securepath_add_library(audio_util *.cpp *.hpp detail/*.cpp detail/*.hpp)
target_link_libraries(audio_util PUBLIC audio util log)
