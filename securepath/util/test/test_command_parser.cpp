// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/command_parser.hpp>

#include <fstream>

namespace securepath::test {

struct test_menu : command_parser {
	bool help = false;
	std::string order;
	int number = 0;

	test_menu() {
		add(help, "help", "h", "help me");
		add(order, "order", "o", "what to order");
		add(number, "number", "x", "number n");
	}
};

struct vector_menu : command_parser {
	std::vector<int> numbers;
	std::vector<std::string> names;

	vector_menu() {
		add(numbers, "numbers", "i", "show numbers");
		add(names, "names", "s", "show names");
	}
};

TEST_CASE("command_parser quoted argument", "[command_parser]") {
	test_menu menu;
	menu.parse("--order \"cheese burger\"");
	CHECK(menu.order == "cheese burger");
}

TEST_CASE("command_parser unterminated quote throws", "[command_parser]") {
	// pre-fix: infinite loop appending EOF characters
	test_menu menu;
	CHECK_THROWS_AS(menu.parse("--order \"unterminated"), invalid_argument);
}

TEST_CASE("command_parser double vector command", "[command_parser]") {

	vector_menu vm;
	vm.parse("--names alfa --names beta");
	CHECK(vm.names.size() == 1);
	CHECK(vm.names[0] == "beta");

}

TEST_CASE("command_parser vector menu", "[command_parser]") {

	vector_menu vm;
	CHECK(vm.numbers.size() == 0);
	CHECK(vm.names.size() == 0);

	vm.parse("--numbers");
	vm.parse("--names");

	CHECK(vm.numbers.size() == 0);
	CHECK(vm.names.size() == 0);	

	vm.parse("--numbers 3 5 4");
	CHECK(vm.numbers.size() == 3);
	CHECK(vm.numbers[0] == 3);
	CHECK(vm.numbers[1] == 5);
	CHECK(vm.numbers[2] == 4);

	vm.parse("--numbers 6 7");
	CHECK(vm.numbers.size() == 2);
	CHECK(vm.numbers[0] == 6);
	CHECK(vm.numbers[1] == 7);

	vm.parse("--names alfa beta gamma");
	CHECK(vm.names.size() == 3);
	CHECK(vm.names[0] == "alfa");
	CHECK(vm.names[1] == "beta");
	CHECK(vm.names[2] == "gamma");

}

TEST_CASE("command parser basics", "[command_parser]") {

	test_menu tm;
	CHECK(!tm.help);
	CHECK(tm.order == "");
	CHECK(tm.number == 0);

	tm.parse("--help");
	CHECK(tm.help);
	
	tm.parse("--order beer");
	CHECK(tm.order == "beer");

	tm.parse("-o more_beer");
	CHECK(tm.order == "more_beer");

	tm.parse("--number 1");
	CHECK(tm.number == 1);

}

TEST_CASE("command_parser bad arguments", "[command_parser]") {

	vector_menu vm;
	CHECK_THROWS_AS(vm.parse("--numbers bb"), std::exception);
	CHECK_THROWS_AS(vm.parse("--numbers !"), std::exception);
	test_menu tm;
	CHECK_THROWS_AS(tm.parse("--number b"), std::exception);
	CHECK_THROWS_AS(tm.parse("--number #"), std::exception);

}

TEST_CASE("command_parser exception", "[command_parser]") {

	test_menu tm;
	CHECK_THROWS_AS(tm.parse("--order"), std::exception);
	CHECK_THROWS_AS(tm.parse("--order too many"), std::exception);

}

TEST_CASE("command_parser parse", "[command_parser]") {

	test_menu tm;
	std::string str = "--order beer";
	std::istringstream in(str);
	tm.parse(in);
	CHECK(tm.order == "beer");

	std::string str2 = "-o beers";
	std::istringstream in2(str2);
	tm.parse(in2);
	CHECK(tm.order == "beers");

	std::string str3 = "--order milk";
	tm.parse(str3);
	CHECK(tm.order == "milk");
	
	char const* args[] = {"dump", "--order","water"};
	tm.parse(3, (char**)args);
	CHECK(tm.order == "water");

}

TEST_CASE("command_parser parse file", "[command_parser]") {

	std::remove("test.cfg");
	test_menu tm;
	CHECK(tm.order == "");
	CHECK(tm.number == 0);

	std::ofstream out("test.cfg");
	out << "\norder beer\n";
	out.close();

	tm.parse_file("test.cfg");
	CHECK(tm.order == "");
	CHECK(tm.number == 0);

	out.open("test.cfg");
	out << "\n--order beer\n-x 1";
	out.close();
	
	tm.parse_file("test.cfg");
	CHECK(tm.order == "beer");
	CHECK(tm.number == 1);

	std::remove("test.cfg");

}

TEST_CASE("command_parser print help", "[command_parser]") {

	test_menu tm;
	std::ostringstream os;
	tm.print_help(os);
	std::string s = os.str();
	CHECK(s.find("--order") != std::string::npos);
	CHECK(s.find("-x") != std::string::npos);
	CHECK(s.find("what to order") != std::string::npos);

}

}
