// Local-only RandomX header fixture helper for WAM regression tests.
//
// Given the displayed RandomX seed hash and a serialized 80-byte block header,
// verify that the original header satisfies its nBits target, then deterministically
// find a nonce using the same seed whose RandomX hash does not satisfy the target.
// No networking or node interaction occurs here.

#include <randomx.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using boost::multiprecision::cpp_int;

static unsigned char hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
    throw std::runtime_error("invalid hex");
}

static std::vector<unsigned char> parse_hex(const std::string& s)
{
    if ((s.size() % 2) != 0) throw std::runtime_error("hex length must be even");
    std::vector<unsigned char> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>((hex_nibble(s[2 * i]) << 4) | hex_nibble(s[2 * i + 1]));
    }
    return out;
}

static std::string to_hex(const unsigned char* data, size_t len)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) ss << std::setw(2) << static_cast<unsigned>(data[i]);
    return ss.str();
}

static cpp_int little_endian_integer(const unsigned char* data, size_t len)
{
    cpp_int value = 0;
    for (size_t i = len; i > 0; --i) {
        value <<= 8;
        value += data[i - 1];
    }
    return value;
}

static cpp_int compact_target(uint32_t bits)
{
    const uint32_t size = bits >> 24;
    const uint32_t word = bits & 0x007fffffU;
    if ((bits & 0x00800000U) != 0 || word == 0) {
        throw std::runtime_error("invalid compact target");
    }

    cpp_int target = word;
    if (size <= 3) {
        target >>= 8 * (3 - size);
    } else {
        target <<= 8 * (size - 3);
    }
    return target;
}

static uint32_t read_le32(const unsigned char* p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static void write_le32(unsigned char* p, uint32_t v)
{
    p[0] = static_cast<unsigned char>(v & 0xff);
    p[1] = static_cast<unsigned char>((v >> 8) & 0xff);
    p[2] = static_cast<unsigned char>((v >> 16) & 0xff);
    p[3] = static_cast<unsigned char>((v >> 24) & 0xff);
}

int main(int argc, char** argv)
{
    try {
        if (argc != 3) {
            std::cerr << "usage: randomx_header_probe <display-seed-hex> <80-byte-header-hex>\n";
            return 2;
        }

        auto seed_display = parse_hex(argv[1]);
        auto header = parse_hex(argv[2]);
        if (seed_display.size() != 32) throw std::runtime_error("seed must be 32 bytes");
        if (header.size() != 80) throw std::runtime_error("header must be exactly 80 bytes");

        // uint256::GetHex() displays the reverse of the internal byte order used by
        // seed.begin(). WAM passes seed.begin() directly to randomx_init_cache().
        std::reverse(seed_display.begin(), seed_display.end());

        const uint32_t bits = read_le32(header.data() + 72);
        const cpp_int target = compact_target(bits);

        const randomx_flags flags = static_cast<randomx_flags>(
            static_cast<int>(randomx_get_flags()) & ~static_cast<int>(RANDOMX_FLAG_FULL_MEM));

        randomx_cache* cache = randomx_alloc_cache(flags);
        if (!cache) throw std::runtime_error("randomx_alloc_cache failed");
        randomx_init_cache(cache, seed_display.data(), seed_display.size());

        randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);
        if (!vm) {
            randomx_release_cache(cache);
            throw std::runtime_error("randomx_create_vm failed");
        }

        auto calc = [&](const std::vector<unsigned char>& h) {
            std::array<unsigned char, RANDOMX_HASH_SIZE> out{};
            randomx_calculate_hash(vm, h.data(), h.size(), out.data());
            return out;
        };

        const auto original_hash = calc(header);
        if (little_endian_integer(original_hash.data(), original_hash.size()) > target) {
            randomx_destroy_vm(vm);
            randomx_release_cache(cache);
            throw std::runtime_error(
                "original node-mined header does not satisfy target with supplied seed");
        }

        const uint32_t original_nonce = read_le32(header.data() + 76);
        bool found = false;
        std::array<unsigned char, RANDOMX_HASH_SIZE> invalid_hash{};
        uint32_t invalid_nonce = 0;

        // Regtest uses a very easy target, so a failing nonce appears quickly.
        // Keep the search bounded to preserve deterministic CI behavior.
        for (uint32_t nonce = 0; nonce < 4096; ++nonce) {
            if (nonce == original_nonce) continue;
            write_le32(header.data() + 76, nonce);
            const auto hash = calc(header);
            if (little_endian_integer(hash.data(), hash.size()) > target) {
                invalid_hash = hash;
                invalid_nonce = nonce;
                found = true;
                break;
            }
        }

        randomx_destroy_vm(vm);
        randomx_release_cache(cache);

        if (!found) {
            std::cerr << "no invalid nonce found inside bounded search\n";
            return 3;
        }

        std::cout << "header=" << to_hex(header.data(), header.size()) << "\n";
        std::cout << "pow_hash_internal=" << to_hex(invalid_hash.data(), invalid_hash.size()) << "\n";
        std::cout << "nonce=" << invalid_nonce << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
