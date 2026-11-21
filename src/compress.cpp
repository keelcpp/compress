#include "keel/compress.h"

#include "keel/arena.h"

namespace keel::compress {

namespace {

struct Crc32Table {
    u32 entries[256]{};
};

consteval Crc32Table make_crc32_table() noexcept {
    Crc32Table tbl{};
    for (u32 i = 0; i < 256; ++i) {
        u32 c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        tbl.entries[i] = c;
    }
    return tbl;
}

constexpr Crc32Table kCrc32Table = make_crc32_table();

class BitReader {
public:
    BitReader(const u8* src, usize len) noexcept : m_data(src), m_len(len) {}

    [[nodiscard]] bool read_bits(int n, u32& out) noexcept {
        KEEL_ASSERT(n >= 0 && n <= 24);
        while (m_bit_count < n) {
            if (m_pos >= m_len) [[unlikely]] {
                return false;
            }
            m_bit_buf |= (static_cast<u32>(m_data[m_pos++]) << m_bit_count);
            m_bit_count += 8;
        }
        out = (n == 0) ? 0u : (m_bit_buf & ((1u << n) - 1u));
        m_bit_buf >>= n;
        m_bit_count -= n;
        return true;
    }

    void align_to_byte() noexcept {
        m_bit_buf = 0;
        m_bit_count = 0;
    }

    [[nodiscard]] bool read_u16_le(u16& out) noexcept {
        KEEL_ASSERT(m_bit_count == 0);
        if (m_len - m_pos < 2) [[unlikely]] {
            return false;
        }
        out = static_cast<u16>(static_cast<u16>(m_data[m_pos]) | (static_cast<u16>(m_data[m_pos + 1]) << 8));
        m_pos += 2;
        return true;
    }

    [[nodiscard]] const u8* current_ptr() const noexcept { return m_data + m_pos; }
    [[nodiscard]] usize remaining_bytes() const noexcept { return (m_pos <= m_len) ? (m_len - m_pos) : 0; }
    [[nodiscard]] usize consumed_bytes() const noexcept { return m_pos; }

    void skip_bytes(usize count) noexcept {
        KEEL_ASSERT(m_bit_count == 0 && count <= remaining_bytes());
        m_pos += count;
    }

private:
    const u8* m_data = nullptr;
    usize m_len = 0;
    usize m_pos = 0;
    u32 m_bit_buf = 0;
    int m_bit_count = 0;
};

struct HuffmanTree {
    static constexpr int kMaxBits = 15;

    ArenaArray<i16> nodes; // left = 2*node, right = 2*node + 1; negative = -(symbol + 1), 0 = unassigned

    explicit HuffmanTree(Arena& scratch) : nodes(scratch, 576) {}

    [[nodiscard]] ErrorCode build(const u8* lens, int count) {
        nodes.clear();
        nodes.push_back(0);
        nodes.push_back(0);

        int max_len = 0;
        int bl_count[kMaxBits + 1] = {};
        for (int i = 0; i < count; ++i) {
            const int len = static_cast<int>(lens[i]);
            if (len > kMaxBits) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
            if (len > 0) {
                ++bl_count[len];
                if (len > max_len) {
                    max_len = len;
                }
            }
        }
        if (max_len == 0) {
            return ErrorCode::Ok;
        }

        // Reject over-subscribed code length sets (RFC 1951 §3.2.2)
        int left = 1;
        for (int bits = 1; bits <= max_len; ++bits) {
            left <<= 1;
            left -= bl_count[bits];
            if (left < 0) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
        }

        int next_code[kMaxBits + 1] = {};
        int code = 0;
        for (int bits = 1; bits <= max_len; ++bits) {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for (int i = 0; i < count; ++i) {
            const int len = static_cast<int>(lens[i]);
            if (len == 0) continue;
            const int c = next_code[len]++;
            int node = 0;
            for (int b = len - 1; b >= 0; --b) {
                const int bit = (c >> b) & 1;
                const usize child_idx = static_cast<usize>(node * 2 + bit);
                if (b == 0) {
                    if (nodes[child_idx] != 0) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }
                    nodes[child_idx] = static_cast<i16>(-(i + 1));
                } else {
                    i16 child = nodes[child_idx];
                    if (child < 0) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }
                    if (child == 0) {
                        const int new_node = static_cast<int>(nodes.size() / 2);
                        nodes[child_idx] = static_cast<i16>(new_node);
                        nodes.push_back(0);
                        nodes.push_back(0);
                        child = static_cast<i16>(new_node);
                    }
                    node = static_cast<int>(child);
                }
            }
        }
        return ErrorCode::Ok;
    }

    [[nodiscard]] ErrorCode decode(BitReader& br, int& sym_out) const noexcept {
        const i16* tree_data = nodes.data();
        int node = 0;
        while (true) {
            u32 bit = 0;
            if (!br.read_bits(1, bit)) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            const i16 child = tree_data[static_cast<usize>(node * 2) + static_cast<usize>(bit)];
            if (child < 0) {
                sym_out = static_cast<int>(-child) - 1;
                return ErrorCode::Ok;
            }
            if (child == 0) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
            node = static_cast<int>(child);
        }
    }
};

constexpr int kExtraLengthBits[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};

constexpr int kLengthBase[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};

constexpr int kExtraDistBits[30] = {
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

constexpr int kDistBase[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,   33,   49,   65,    97,    129,
    193,  257,  385,  513,  769,  1025, 1537, 2049,  3073,  4097, 6145, 8193, 12289, 16385, 24577,
};

constexpr int kCodeLengthOrder[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
};

void build_fixed_trees(HuffmanTree& lit_tree, HuffmanTree& dist_tree) {
    u8 lit_lens[288];
    for (int i = 0; i <= 143; ++i) lit_lens[i] = 8;
    for (int i = 144; i <= 255; ++i) lit_lens[i] = 9;
    for (int i = 256; i <= 279; ++i) lit_lens[i] = 7;
    for (int i = 280; i <= 287; ++i) lit_lens[i] = 8;
    [[maybe_unused]] const ErrorCode ec1 = lit_tree.build(lit_lens, 288);
    KEEL_ASSERT(ec1 == ErrorCode::Ok);

    u8 dist_lens[32];
    for (int i = 0; i < 32; ++i) dist_lens[i] = 5;
    [[maybe_unused]] const ErrorCode ec2 = dist_tree.build(dist_lens, 32);
    KEEL_ASSERT(ec2 == ErrorCode::Ok);
}

[[nodiscard]] Result<Array<u8>> inflate_raw_impl(ArrayRef<u8> src, const InflateOptions& opts, usize* out_consumed) {
    Allocator* dst_alloc = opts.allocator ? opts.allocator : default_allocator();
    Array<u8> out(dst_alloc);

    if (opts.expected_size_hint > 0) {
        constexpr usize kMaxInitialReserve = 16ULL * 1024 * 1024;
        usize reserve_cap = keel::min(opts.expected_size_hint, kMaxInitialReserve);
        if (opts.max_output_bytes > 0) {
            reserve_cap = keel::min(reserve_cap, opts.max_output_bytes);
        }
        out.reserve(reserve_cap);
    }

    auto exceeds_cap = [&](usize add_bytes) noexcept -> bool {
        if (opts.max_output_bytes == 0) return false;
        return add_bytes > opts.max_output_bytes || out.size() > (opts.max_output_bytes - add_bytes);
    };

    ArenaTemp scratch = get_scratch(dst_alloc);
    HuffmanTree lit_tree(scratch.arena());
    HuffmanTree dist_tree(scratch.arena());
    HuffmanTree cl_tree(scratch.arena());

    BitReader br(src.data(), src.size());
    bool bfinal = false;

    while (!bfinal) {
        u32 bfinal_bit = 0;
        u32 btype = 0;
        if (!br.read_bits(1, bfinal_bit) || !br.read_bits(2, btype)) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        bfinal = (bfinal_bit != 0);

        if (btype == 0) {
            br.align_to_byte();
            u16 blen = 0;
            u16 nlen = 0;
            if (!br.read_u16_le(blen) || !br.read_u16_le(nlen)) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            if (static_cast<u16>(blen ^ 0xFFFFu) != nlen) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
            if (br.remaining_bytes() < blen) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            if (exceeds_cap(blen)) [[unlikely]] {
                return ErrorCode::OutOfRange;
            }
            if (blen > 0) {
                out.append(ArrayRef<u8>(br.current_ptr(), blen));
                br.skip_bytes(blen);
            }
        } else if (btype == 1 || btype == 2) {
            if (btype == 1) {
                build_fixed_trees(lit_tree, dist_tree);
            } else {
                u32 hlit_raw = 0;
                u32 hdist_raw = 0;
                u32 hclen_raw = 0;
                if (!br.read_bits(5, hlit_raw) || !br.read_bits(5, hdist_raw) || !br.read_bits(4, hclen_raw))
                    [[unlikely]] {
                    return ErrorCode::EndOfFile;
                }
                const int hlit = static_cast<int>(hlit_raw) + 257;
                const int hdist = static_cast<int>(hdist_raw) + 1;
                const int hclen = static_cast<int>(hclen_raw) + 4;
                if (hlit > 286 || hdist > 30) [[unlikely]] {
                    return ErrorCode::InvalidData;
                }

                u8 cl_code_lens[19] = {};
                for (int i = 0; i < hclen; ++i) {
                    u32 cl_val = 0;
                    if (!br.read_bits(3, cl_val)) [[unlikely]] {
                        return ErrorCode::EndOfFile;
                    }
                    cl_code_lens[kCodeLengthOrder[i]] = static_cast<u8>(cl_val);
                }

                const ErrorCode cl_ec = cl_tree.build(cl_code_lens, 19);
                if (cl_ec != ErrorCode::Ok) [[unlikely]] {
                    return cl_ec;
                }

                const int total_codes = hlit + hdist;
                u8 all_lens[320] = {};
                int idx = 0;
                while (idx < total_codes) {
                    int sym = 0;
                    const ErrorCode dec_ec = cl_tree.decode(br, sym);
                    if (dec_ec != ErrorCode::Ok) [[unlikely]] {
                        return dec_ec;
                    }
                    if (sym < 16) {
                        all_lens[idx++] = static_cast<u8>(sym);
                    } else if (sym == 16) {
                        if (idx == 0) [[unlikely]] {
                            return ErrorCode::InvalidData;
                        }
                        u32 rep_extra = 0;
                        if (!br.read_bits(2, rep_extra)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        const int rep = static_cast<int>(rep_extra) + 3;
                        if (idx + rep > total_codes) [[unlikely]] {
                            return ErrorCode::InvalidData;
                        }
                        const u8 prev = all_lens[idx - 1];
                        for (int r = 0; r < rep; ++r) {
                            all_lens[idx++] = prev;
                        }
                    } else if (sym == 17 || sym == 18) {
                        u32 rep_extra = 0;
                        const int extra_bits = (sym == 17) ? 3 : 7;
                        const int base_rep = (sym == 17) ? 3 : 11;
                        if (!br.read_bits(extra_bits, rep_extra)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        const int rep = static_cast<int>(rep_extra) + base_rep;
                        if (idx + rep > total_codes) [[unlikely]] {
                            return ErrorCode::InvalidData;
                        }
                        for (int r = 0; r < rep; ++r) {
                            all_lens[idx++] = 0;
                        }
                    } else {
                        return ErrorCode::InvalidData;
                    }
                }

                // End-of-block symbol 256 must have non-zero code length in every dynamic block
                if (all_lens[256] == 0) [[unlikely]] {
                    return ErrorCode::InvalidData;
                }

                const ErrorCode lit_ec = lit_tree.build(all_lens, hlit);
                if (lit_ec != ErrorCode::Ok) [[unlikely]] {
                    return lit_ec;
                }
                const ErrorCode dist_ec = dist_tree.build(all_lens + hlit, hdist);
                if (dist_ec != ErrorCode::Ok) [[unlikely]] {
                    return dist_ec;
                }
            }

            while (true) {
                int sym = 0;
                const ErrorCode sym_ec = lit_tree.decode(br, sym);
                if (sym_ec != ErrorCode::Ok) [[unlikely]] {
                    return sym_ec;
                }

                if (sym < 256) {
                    if (exceeds_cap(1)) [[unlikely]] {
                        return ErrorCode::OutOfRange;
                    }
                    out.push_back(static_cast<u8>(sym));
                } else if (sym == 256) {
                    break;
                } else if (sym <= 285) {
                    const int len_idx = sym - 257;
                    usize length = static_cast<usize>(kLengthBase[len_idx]);
                    const int extra_bits = kExtraLengthBits[len_idx];
                    if (extra_bits > 0) {
                        u32 extra_val = 0;
                        if (!br.read_bits(extra_bits, extra_val)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        length += static_cast<usize>(extra_val);
                    }

                    int dist_sym = 0;
                    const ErrorCode dist_ec = dist_tree.decode(br, dist_sym);
                    if (dist_ec != ErrorCode::Ok) [[unlikely]] {
                        return dist_ec;
                    }
                    if (dist_sym < 0 || dist_sym >= 30) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }

                    usize dist = static_cast<usize>(kDistBase[dist_sym]);
                    const int extra_dist_bits = kExtraDistBits[dist_sym];
                    if (extra_dist_bits > 0) {
                        u32 extra_val = 0;
                        if (!br.read_bits(extra_dist_bits, extra_val)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        dist += static_cast<usize>(extra_val);
                    }

                    if (dist > out.size()) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }
                    if (exceeds_cap(length)) [[unlikely]] {
                        return ErrorCode::OutOfRange;
                    }

                    const usize old_size = out.size();
                    out.resize(old_size + length);
                    u8* dst = out.data() + old_size;
                    const u8* copy_src = dst - dist;
                    if (dist >= length) {
                        mem_copy(dst, copy_src, length);
                    } else if (dist == 1) {
                        mem_set(dst, *copy_src, length);
                    } else {
                        for (usize k = 0; k < length; ++k) {
                            dst[k] = copy_src[k];
                        }
                    }
                } else {
                    return ErrorCode::InvalidData;
                }
            }
        } else {
            return ErrorCode::InvalidData;
        }
    }

    if (out_consumed) {
        *out_consumed = br.consumed_bytes();
    }
    return out;
}

class BitWriter {
public:
    explicit BitWriter(Array<u8>& dst) noexcept : m_bytes(dst) {}

    void write_bits(u32 val, int n) {
        KEEL_ASSERT(n >= 0 && n <= 24);
        m_bit_buf |= (val << m_bit_count);
        m_bit_count += n;
        while (m_bit_count >= 8) {
            m_bytes.push_back(static_cast<u8>(m_bit_buf & 0xFFu));
            m_bit_buf >>= 8;
            m_bit_count -= 8;
        }
    }

    void align_to_byte() {
        if (m_bit_count > 0) {
            m_bytes.push_back(static_cast<u8>(m_bit_buf & 0xFFu));
            m_bit_buf = 0;
            m_bit_count = 0;
        }
    }

    void write_bytes(const u8* data, usize len) {
        align_to_byte();
        if (len > 0) {
            m_bytes.append(ArrayRef<u8>(data, len));
        }
    }

private:
    Array<u8>& m_bytes;
    u32 m_bit_buf = 0;
    int m_bit_count = 0;
};

struct FixedCode {
    u16 bits = 0;
    u8 len = 0;
};

consteval u16 bit_reverse(u16 val, int len) noexcept {
    u16 res = 0;
    for (int i = 0; i < len; ++i) {
        res = static_cast<u16>((res << 1) | ((val >> i) & 1u));
    }
    return res;
}

struct FixedLitTable {
    FixedCode codes[288]{};
    u8 dist_codes[30]{};
};

consteval FixedLitTable make_fixed_lit_table() noexcept {
    FixedLitTable tbl{};
    for (int sym = 0; sym < 288; ++sym) {
        if (sym <= 143) {
            tbl.codes[sym] = {bit_reverse(static_cast<u16>(0x30 + sym), 8), 8};
        } else if (sym <= 255) {
            tbl.codes[sym] = {bit_reverse(static_cast<u16>(0x190 + (sym - 144)), 9), 9};
        } else if (sym <= 279) {
            tbl.codes[sym] = {bit_reverse(static_cast<u16>(sym - 256), 7), 7};
        } else {
            tbl.codes[sym] = {bit_reverse(static_cast<u16>(0xC0 + (sym - 280)), 8), 8};
        }
    }
    for (int d = 0; d < 30; ++d) {
        tbl.dist_codes[d] = static_cast<u8>(bit_reverse(static_cast<u16>(d), 5));
    }
    return tbl;
}

constexpr FixedLitTable kFixedLitTable = make_fixed_lit_table();

void deflate_into(Array<u8>& out, ArrayRef<u8> src, int level) {
    const u8* data = src.data();
    const usize len = src.size();
    BitWriter bw(out);

    if (level <= 0) {
        usize pos = 0;
        while (pos < len || len == 0) {
            const usize chunk = keel::min<usize>(len - pos, 65535u);
            const bool is_last = (pos + chunk >= len);
            bw.write_bits(is_last ? 1u : 0u, 1);
            bw.write_bits(0u, 2); // BTYPE = 00
            bw.align_to_byte();
            const u16 blen = static_cast<u16>(chunk);
            const u16 nlen = static_cast<u16>(~blen);
            bw.write_bits(blen, 16);
            bw.write_bits(nlen, 16);
            if (chunk > 0) {
                bw.write_bytes(data + pos, chunk);
            }
            pos += chunk;
            if (pos >= len) break;
        }
        bw.align_to_byte();
        return;
    }

    bw.write_bits(1u, 1); // BFINAL = 1
    bw.write_bits(1u, 2); // BTYPE = 01 (Fixed Huffman)

    constexpr usize kHashSize = 32768;
    constexpr usize kWindowSize = 32768;
    constexpr usize kMinMatch = 3;
    constexpr usize kMaxMatch = 258;

    ArenaTemp scratch = get_scratch(out.allocator());
    usize* head = scratch.arena().alloc_array<usize>(kHashSize);
    usize* prev = scratch.arena().alloc_array<usize>(kWindowSize);
    mem_set(head, 0xFF, kHashSize * sizeof(usize));   // kInvalidIndex (~usize{0})
    mem_set(prev, 0xFF, kWindowSize * sizeof(usize)); // kInvalidIndex (~usize{0})

    auto hash3 = [](const u8* p) noexcept -> usize {
        return ((static_cast<usize>(p[0]) << 10) ^ (static_cast<usize>(p[1]) << 5) ^ static_cast<usize>(p[2])) &
               (kHashSize - 1);
    };

    const int max_chain = (level <= 3) ? 4 : ((level <= 6) ? 16 : 64);

    usize pos = 0;
    while (pos < len) {
        usize best_len = 0;
        usize best_dist = 0;

        if (pos + kMinMatch <= len) {
            const usize h = hash3(data + pos);
            usize match_pos = head[h];
            prev[pos & (kWindowSize - 1)] = match_pos;
            head[h] = pos;

            int chain_limit = max_chain;
            const usize max_len_possible = keel::min<usize>(len - pos, kMaxMatch);
            while (match_pos != kInvalidIndex && (pos - match_pos) <= kWindowSize && chain_limit-- > 0) {
                const usize cur_dist = pos - match_pos;
                if (data[pos + best_len] == data[match_pos + best_len]) {
                    usize mlen = 0;
                    while (mlen < max_len_possible && data[pos + mlen] == data[match_pos + mlen]) {
                        ++mlen;
                    }
                    if (mlen > best_len) {
                        best_len = mlen;
                        best_dist = cur_dist;
                        if (best_len >= max_len_possible) break;
                    }
                }
                match_pos = prev[match_pos & (kWindowSize - 1)];
            }
        }

        if (best_len >= kMinMatch) {
            int len_idx = 0;
            for (int i = 0; i < 29; ++i) {
                if (static_cast<usize>(kLengthBase[i]) <= best_len) {
                    len_idx = i;
                } else {
                    break;
                }
            }
            const FixedCode lit_code = kFixedLitTable.codes[257 + len_idx];
            bw.write_bits(lit_code.bits, lit_code.len);
            const int extra_len_bits = kExtraLengthBits[len_idx];
            if (extra_len_bits > 0) {
                bw.write_bits(static_cast<u32>(best_len - static_cast<usize>(kLengthBase[len_idx])), extra_len_bits);
            }

            int dist_idx = 0;
            for (int i = 0; i < 30; ++i) {
                if (static_cast<usize>(kDistBase[i]) <= best_dist) {
                    dist_idx = i;
                } else {
                    break;
                }
            }
            bw.write_bits(kFixedLitTable.dist_codes[dist_idx], 5);
            const int extra_dist_bits = kExtraDistBits[dist_idx];
            if (extra_dist_bits > 0) {
                bw.write_bits(static_cast<u32>(best_dist - static_cast<usize>(kDistBase[dist_idx])), extra_dist_bits);
            }

            for (usize k = 1; k < best_len; ++k) {
                if (pos + k + kMinMatch <= len) {
                    const usize h = hash3(data + pos + k);
                    prev[(pos + k) & (kWindowSize - 1)] = head[h];
                    head[h] = pos + k;
                }
            }
            pos += best_len;
        } else {
            const FixedCode lit_code = kFixedLitTable.codes[data[pos++]];
            bw.write_bits(lit_code.bits, lit_code.len);
        }
    }

    const FixedCode eob = kFixedLitTable.codes[256];
    bw.write_bits(eob.bits, eob.len);
    bw.align_to_byte();
}

} // namespace

u32 crc32_update(u32 crc, ArrayRef<u8> data) noexcept {
    u32 c = crc ^ 0xFFFFFFFFu;
    const u8* ptr = data.data();
    const usize len = data.size();
    for (usize i = 0; i < len; ++i) {
        c = kCrc32Table.entries[(c ^ ptr[i]) & 0xFFu] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

u32 adler32_update(u32 adler, ArrayRef<u8> data) noexcept {
    constexpr u32 kBase = 65521u;
    u32 s1 = adler & 0xFFFFu;
    u32 s2 = (adler >> 16) & 0xFFFFu;

    const u8* ptr = data.data();
    usize len = data.size();
    while (len > 0) {
        usize k = (len < 5552u) ? len : 5552u;
        len -= k;
        while (k >= 16u) {
            s1 += ptr[0];
            s2 += s1;
            s1 += ptr[1];
            s2 += s1;
            s1 += ptr[2];
            s2 += s1;
            s1 += ptr[3];
            s2 += s1;
            s1 += ptr[4];
            s2 += s1;
            s1 += ptr[5];
            s2 += s1;
            s1 += ptr[6];
            s2 += s1;
            s1 += ptr[7];
            s2 += s1;
            s1 += ptr[8];
            s2 += s1;
            s1 += ptr[9];
            s2 += s1;
            s1 += ptr[10];
            s2 += s1;
            s1 += ptr[11];
            s2 += s1;
            s1 += ptr[12];
            s2 += s1;
            s1 += ptr[13];
            s2 += s1;
            s1 += ptr[14];
            s2 += s1;
            s1 += ptr[15];
            s2 += s1;
            ptr += 16;
            k -= 16;
        }
        while (k > 0) {
            s1 += *ptr++;
            s2 += s1;
            --k;
        }
        s1 %= kBase;
        s2 %= kBase;
    }
    return (s2 << 16) | s1;
}

Result<Array<u8>> inflate_raw(ArrayRef<u8> src, const InflateOptions& opts) {
    return inflate_raw_impl(src, opts, nullptr);
}

Array<u8> deflate_raw(ArrayRef<u8> src, int level, Allocator* alloc) {
    Array<u8> out(alloc);
    out.reserve((src.size() / 2) + 32);
    deflate_into(out, src, level);
    return out;
}

Result<Array<u8>> zlib_decompress(ArrayRef<u8> src, const InflateOptions& opts) {
    if (src.size() < 6) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }

    const u8 cmf = src[0];
    const u8 flg = src[1];
    if (((static_cast<u32>(cmf) << 8) + static_cast<u32>(flg)) % 31u != 0u) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    if ((cmf & 0x0Fu) != 8u || (cmf >> 4) > 7u) [[unlikely]] {
        return ErrorCode::NotSupported;
    }
    if ((flg & 0x20u) != 0u) [[unlikely]] {
        return ErrorCode::NotSupported;
    }

    usize consumed_deflate = 0;
    KEEL_TRY_ASSIGN(Array<u8> uncompressed, inflate_raw_impl(src.slice(2, src.size() - 6), opts, &consumed_deflate));

    const usize adler_pos = 2 + consumed_deflate;
    if (adler_pos + 4 > src.size()) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }
    const u32 expected_adler = (static_cast<u32>(src[adler_pos]) << 24) | (static_cast<u32>(src[adler_pos + 1]) << 16) |
                               (static_cast<u32>(src[adler_pos + 2]) << 8) | static_cast<u32>(src[adler_pos + 3]);
    const u32 actual_adler = adler32(uncompressed);
    if (expected_adler != actual_adler) [[unlikely]] {
        return ErrorCode::InvalidData;
    }

    return uncompressed;
}

Array<u8> zlib_compress(ArrayRef<u8> src, int level, Allocator* alloc) {
    Array<u8> out(alloc);
    out.reserve((src.size() / 2) + 64);

    // CMF = 0x78 (Deflate, 32 KiB window)
    const u8 cmf = 0x78u;
    u8 flg = (level <= 0) ? 0x00u : ((level <= 3) ? 0x40u : ((level <= 6) ? 0x80u : 0xC0u));
    const u32 rem = ((static_cast<u32>(cmf) << 8) + static_cast<u32>(flg)) % 31u;
    if (rem != 0u) {
        flg = static_cast<u8>(flg + (31u - rem));
    }

    out.push_back(cmf);
    out.push_back(flg);

    deflate_into(out, src, level);

    const u32 adler = adler32(src);
    out.push_back(static_cast<u8>((adler >> 24) & 0xFFu));
    out.push_back(static_cast<u8>((adler >> 16) & 0xFFu));
    out.push_back(static_cast<u8>((adler >> 8) & 0xFFu));
    out.push_back(static_cast<u8>(adler & 0xFFu));

    return out;
}

} // namespace keel::compress
