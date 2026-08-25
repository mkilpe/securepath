securepath_add_library(event_system *.cpp *.hpp impl/*.cpp impl/*.hpp)
target_link_libraries(event_system PUBLIC util asio::asio)
securepath_add_test_directory(test)
