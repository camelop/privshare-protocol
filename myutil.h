//
// Created by Xiaoyuan Liu on 11/22/20.
//

#ifndef MULTIPARTY_DATABASE_MYUTIL_H
#define MULTIPARTY_DATABASE_MYUTIL_H

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <Base64.h>
#include <json.hpp>

using json = nlohmann::json;

using Base64 = macaron::Base64;

uint int_to_uint(int x);
int uint_to_int(uint x);
std::string generate_uuid_v4();
uint64_t string_to_uint64(const std::string& s);
uint64_t string_to_number(const std::string& s, int bit_length);
std::string generate_string_digest(std::string target, std::string desc="");

extern std::vector<std::pair<
        std::pair<std::string, bool>,
        std::chrono::time_point<std::chrono::system_clock>
        > > Report_timing_timestamps;
void report_timing(std::string event_name, bool is_start, bool print_report=true);
json report_all_timestamps();

#endif //MULTIPARTY_DATABASE_MYUTIL_H
