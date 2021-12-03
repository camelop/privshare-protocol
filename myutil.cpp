#include <random>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <bitset>
#include <unordered_map>
#include "myutil.h"
#include "picosha2.h"

uint int_to_uint(int x) {
    return int(x+0x80000000);
}

int uint_to_int(uint x) {
    return uint(x-0x80000000);
}

// credit: happy_sisyphus
// https://stackoverflow.com/questions/24365331/how-can-i-generate-uuid-in-c-without-using-boost-library/58467162
std::string generate_uuid_v4() {
    static std::default_random_engine gen(std::chrono::system_clock::now().time_since_epoch().count());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);
    std::stringstream ss;
    int i;
    ss << std::hex;
    for (i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    ss << dis2(gen);
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (i = 0; i < 12; i++) {
        ss << dis(gen);
    };
    return ss.str();
}

uint64_t string_to_uint64(const std::string& s) {
    std::string hash = "";
    // SHA-256 hashing + use "xor" to reduce to 64 bits
    picosha2::hash256_hex_string(s.begin(), s.end(), hash);  // hash now has length=64
    uint ret = 0;
    // std::cout << hash << std::endl;
    for (int i=0; i<64; i+=8) {
        ret ^= std::stoul(hash.substr(i, 8).c_str(), nullptr, 16);
        // std::cout<<std::bitset<32>(ret) <<std::endl;
    }
    return ret;
}

uint64_t string_to_number(const std::string& s, int bit_length) {
    switch (bit_length) {
        case 64:
            return string_to_uint64(s);
        case 32: {
            uint64_t ret = string_to_uint64(s);
            return (ret ^ (ret >> 32)) & ((1ULL << 32) - 1);
        }
        case 16: {
            uint64_t ret = string_to_number(s, 32);
            return (ret ^ (ret >> 16)) & ((1 << 16) - 1);
        }
        case 8: {
            uint64_t ret = string_to_number(s, 16);
            return (ret ^ (ret >> 8)) & ((1 << 8) - 1);
        }
        default:
            throw std::runtime_error("string_to_number: invalid bit_length");
    }
}

std::string generate_string_digest(std::string target, std::string desc) {
    // generate a short form of the string for debugging purpose
    std::string ret = "<";
    if (desc.size() > 0) {
        ret += desc + ": ";
    };
    ret += "(len=" + std::to_string(target.size())+")";
    ret += "hash-" + std::to_string(string_to_uint64(target));
    ret += ">";
    return ret;
}

std::vector<std::pair<
        std::pair<std::string, bool>,
        std::chrono::time_point<std::chrono::system_clock>
> > Report_timing_timestamps;

void report_timing(std::string event_name, bool is_start, bool print_report) {
    static std::unordered_map<std::string, std::chrono::time_point<std::chrono::system_clock> > event_last;
    auto nw = std::chrono::system_clock::now();
    Report_timing_timestamps.emplace_back(std::make_pair(std::make_pair(event_name, is_start), nw));
    if (is_start) {
        event_last[event_name] = nw;
    } else {
        if (print_report) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(nw - event_last.at(event_name));
            std::cout << "* " << event_name << " " << std::fixed << std::setprecision(2)
                << double(duration.count()) << "ms" << std::endl;
        }
        event_last.erase(event_name);
    }
}

json report_all_timestamps() {
    json ret = json::array();
    if (Report_timing_timestamps.size() < 1) return ret;
    auto& start_timestamp = Report_timing_timestamps.at(0).second;
    for (auto& p: Report_timing_timestamps) {
        auto& event = p.first;
        auto& current_timestamp = p.second;
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(current_timestamp - start_timestamp);
        ret.emplace_back(std::make_pair(event, double(duration.count())));
    }
    return ret;
}
