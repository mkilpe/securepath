securepath_add_library(database *.cpp *.hpp detail/*.cpp detail/*.hpp sqlite/*.cpp sqlite/*.hpp)
target_link_libraries(database PUBLIC util serialisation SQLite3::SQLite3)
securepath_add_test_directory(sqlite/test)
