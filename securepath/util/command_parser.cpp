// SPDX-License-Identifier: MIT

#include "command_parser.hpp"
#include "print_align.hpp"
#include <fstream>

namespace securepath {

void command_parser::parse(int argc, char* args[]) {
	std::string s;
	for(int i = 1; i != argc; ++i) {
		if(i > 1) {
			s += " ";
		}
		std::string arg = args[i];
		if(arg.find(' ') != std::string::npos) {
			arg = '"' + arg + '"';
		}
		s += arg;
	}
	parse(s);
}

void command_parser::parse(std::string s) {
	std::istringstream in(s);
	parse(in);
}

std::string command_parser::parse_name(std::istream& in) {
	std::string s;
	in >> s;
	return s;
}

std::string command_parser::parse_quoted(std::istream& in) {
	std::string s;
	in.ignore(); //the start of quote
	for(; in.good() && in.peek() != '"'; ) {
		s += static_cast<char>(in.get());
	}
	if(!in.good()) {
		throw invalid_argument("unterminated quote in arguments");
	}
	in.ignore(); //the end of quote
	return s;
}

std::string command_parser::parse_arg(std::istream& in) {
	std::string s;
	if(in.peek() == '"') {
		s = parse_quoted(in);
	} else {
		in >> s;
	}
	return s;
}

void command_parser::parse_args(std::istream& in, std::string const& name) {
	std::vector<std::string> args;
	
	for(;in >> std::ws && in.peek() != '-';) {
		std::string a = parse_arg(in);
		if(!a.empty())  {
			args.push_back(std::move(a));
		}
	}
	
	auto it = commands_.find(name);
	if(it == commands_.end()) {
		throw invalid_argument("no parameter named '" + name + "'");
	}
	it->second->extract->parse(args);
}

void command_parser::parse(std::istream& in) {
	for(; in >> std::ws; ) {
		char c = in.peek();
		if(c == '-') {
			parse_args(in, parse_name(in));
		} else {
			parse_arg(in); //for now just ignore positionals
		}
	}
}

void command_parser::print_help(std::ostream& out) {
	for(auto&& v : commands_) {
		if(v.first.substr(0, 2) == "--") {
			auto const& info = *v.second;
			std::string alias;
			if(!info.alias.empty()) {
				alias = ", -" + info.alias;
			}
			std::ostringstream extract_out;
			info.extract->print(extract_out);
			std::string eout = extract_out.str();

			(print_align(out) << "--" << info.name << alias).align(50) << " " << info.info;
			if(!eout.empty()) {
				out << " (" + eout + ")";
			}
			out << std::endl;
		}
	}
}

void command_parser::parse_file(std::string file_name) {
	std::ifstream is(file_name);
	std::string line;
	while(std::getline(is, line)) {
		parse(line);
	}
}

void command_parser::add(bool& var, std::string name, std::string alias, std::string info) {
	add_impl<bool_command>(var, std::move(name), std::move(alias), std::move(info));
}

}
