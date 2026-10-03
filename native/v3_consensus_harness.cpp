#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_int/serialize.hpp>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using boost::multiprecision::cpp_int;

static cpp_int ParseHex(const std::string& s) {
    cpp_int out = 0;
    std::string t = s;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
    for (char c : t) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F') v = 10 + c - 'A';
        else throw std::runtime_error("bad hex");
        out <<= 4;
        out += v;
    }
    return out;
}

static std::string Hex(const cpp_int& v) {
    if (v == 0) return "0";
    cpp_int x = v;
    static const char* digits = "0123456789abcdef";
    std::string out;
    while (x > 0) {
        unsigned d = static_cast<unsigned>((x & 0xf).convert_to<unsigned>());
        out.push_back(digits[d]);
        x >>= 4;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

static cpp_int CompactToTarget(uint32_t compact, bool* negative=nullptr, bool* overflow=nullptr) {
    int size = compact >> 24;
    uint32_t word = compact & 0x007fffffU;
    if (negative) *negative = word != 0 && (compact & 0x00800000U);
    if (overflow) {
        *overflow = word != 0 && (
            size > 34 ||
            (word > 0xffU && size > 33) ||
            (word > 0xffffU && size > 32)
        );
    }
    cpp_int target = word;
    if (size <= 3) target >>= 8 * (3 - size);
    else target <<= 8 * (size - 3);
    return target;
}

static uint32_t TargetToCompact(const cpp_int& target) {
    if (target < 0) throw std::runtime_error("negative target");
    if (target == 0) return 0;

    unsigned bits = boost::multiprecision::msb(target) + 1;
    unsigned size = (bits + 7) / 8;
    cpp_int tmp;
    if (size <= 3) tmp = target << (8 * (3 - size));
    else tmp = target >> (8 * (size - 3));

    uint32_t compact = tmp.convert_to<uint32_t>();
    if (compact & 0x00800000U) {
        compact >>= 8;
        ++size;
    }
    compact &= 0x007fffffU;
    compact |= size << 24;
    return compact;
}

struct Block {
    int64_t time;
    uint32_t bits;
};

static uint32_t DGW(
    const cpp_int& pow_limit,
    int64_t spacing,
    int64_t past,
    int64_t clamp,
    int64_t last_height,
    const std::vector<Block>& blocks)
{
    if (last_height < past) return TargetToCompact(pow_limit);
    if (static_cast<int64_t>(blocks.size()) < past) throw std::runtime_error("short history");

    cpp_int avg = 0;
    for (int64_t count = 1; count <= past; ++count) {
        bool neg=false, ov=false;
        cpp_int target = CompactToTarget(blocks.at(count - 1).bits, &neg, &ov);
        if (neg || ov || target <= 0) throw std::runtime_error("invalid target");
        if (count == 1) avg = target;
        else avg = (avg * count + target) / (count + 1);
    }

    int64_t actual = blocks.front().time - blocks.at(past - 1).time;
    const int64_t expected = past * spacing;
    const int64_t minimum = expected / clamp;
    const int64_t maximum = expected * clamp;
    if (actual < minimum) actual = minimum;
    if (actual > maximum) actual = maximum;

    cpp_int next = avg * actual / expected;
    if (next > pow_limit) next = pow_limit;
    return TargetToCompact(next);
}

static bool CheckPow(const cpp_int& hash, uint32_t bits, const cpp_int& pow_limit) {
    bool negative=false, overflow=false;
    cpp_int target = CompactToTarget(bits, &negative, &overflow);
    if (negative || overflow || target == 0 || target > pow_limit || hash < 0) return false;
    return hash <= target;
}

static int64_t SeedHeight(int64_t epoch, int64_t lag, int64_t height) {
    if (epoch <= 0 || lag < 0 || lag >= epoch || height < 0) throw std::runtime_error("bad seed args");
    if (height <= lag) return 0;
    const int64_t lagged = height - lag;
    return (lagged / epoch) * epoch;
}

static uint32_t ParseU32(const std::string& s) {
    unsigned long long v = std::stoull(s, nullptr, 0);
    if (v > 0xffffffffULL) throw std::runtime_error("uint32 overflow");
    return static_cast<uint32_t>(v);
}

int main(int argc, char** argv) {
    try {
        if (argc < 2) throw std::runtime_error("mode required");
        std::string mode = argv[1];

        if (mode == "compact-to-target") {
            if (argc != 3) throw std::runtime_error("compact-to-target args");
            std::cout << Hex(CompactToTarget(ParseU32(argv[2]))) << "\n";
            return 0;
        }

        if (mode == "target-to-compact") {
            if (argc != 3) throw std::runtime_error("target-to-compact args");
            std::cout << "0x" << std::hex << std::nouppercase << TargetToCompact(ParseHex(argv[2])) << "\n";
            return 0;
        }

        if (mode == "checkpow") {
            if (argc != 5) throw std::runtime_error("checkpow args");
            std::cout << (CheckPow(ParseHex(argv[2]), ParseU32(argv[3]), ParseHex(argv[4])) ? "1" : "0") << "\n";
            return 0;
        }

        if (mode == "seedheight") {
            if (argc != 5) throw std::runtime_error("seedheight args");
            std::cout << SeedHeight(std::stoll(argv[2]), std::stoll(argv[3]), std::stoll(argv[4])) << "\n";
            return 0;
        }

        if (mode == "dgw") {
            if (argc != 8) throw std::runtime_error("dgw args");
            cpp_int pow_limit = ParseHex(argv[2]);
            int64_t spacing = std::stoll(argv[3]);
            int64_t past = std::stoll(argv[4]);
            int64_t clamp = std::stoll(argv[5]);
            int64_t last_height = std::stoll(argv[6]);
            std::vector<Block> blocks;
            std::stringstream series(argv[7]);
            std::string item;
            while (std::getline(series, item, ';')) {
                if (item.empty()) continue;
                auto comma = item.find(',');
                if (comma == std::string::npos) throw std::runtime_error("bad block tuple");
                int64_t time = std::stoll(item.substr(0, comma));
                uint32_t bits = ParseU32(item.substr(comma + 1));
                blocks.push_back({time, bits});
            }
            std::cout << "0x" << std::hex << std::nouppercase
                      << DGW(pow_limit, spacing, past, clamp, last_height, blocks) << "\n";
            return 0;
        }

        throw std::runtime_error("unknown mode");
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}
