#include <randomx.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static unsigned char nibble(char c)
{
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
    throw std::runtime_error("invalid hex");
}

static std::vector<unsigned char> parse_hex(const std::string& s)
{
    if ((s.size() & 1U) != 0) throw std::runtime_error("odd hex length");
    std::vector<unsigned char> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>((nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]));
    }
    return out;
}

static std::string hex(const unsigned char* p, size_t n)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) ss << std::setw(2) << static_cast<unsigned>(p[i]);
    return ss.str();
}

int main(int argc, char** argv)
{
    try {
        if (argc != 3) {
            std::cerr << "usage: pool_job_randomx_probe <internal-seed-hex> <80-byte-header-hex>\n";
            return 2;
        }

        const auto seed = parse_hex(argv[1]);
        const auto header = parse_hex(argv[2]);
        if (seed.size() != 32) throw std::runtime_error("seed must be 32 bytes");
        if (header.size() != 80) throw std::runtime_error("header must be 80 bytes");

        const randomx_flags flags = static_cast<randomx_flags>(
            static_cast<int>(randomx_get_flags()) & ~static_cast<int>(RANDOMX_FLAG_FULL_MEM));

        randomx_cache* cache = randomx_alloc_cache(flags);
        if (!cache) throw std::runtime_error("randomx_alloc_cache failed");
        randomx_init_cache(cache, seed.data(), seed.size());

        randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);
        if (!vm) {
            randomx_release_cache(cache);
            throw std::runtime_error("randomx_create_vm failed");
        }

        std::array<unsigned char, RANDOMX_HASH_SIZE> out{};
        randomx_calculate_hash(vm, header.data(), header.size(), out.data());

        randomx_destroy_vm(vm);
        randomx_release_cache(cache);

        std::cout << "hash=" << hex(out.data(), out.size()) << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
