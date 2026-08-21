securepath_add_library(serialisation *.cpp *.hpp codec/*.cpp codec/*.hpp codec/asn_der/*.cpp codec/asn_der/*.hpp)
target_link_libraries(serialisation PUBLIC util)
securepath_add_test_directory(test codec/asn_der/test)
