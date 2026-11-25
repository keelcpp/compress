#include "keel/compress/deflate.h"

#include "keel/arena.h"
#include "keel/compress/checksum.h"
#include "keel/memory.h"

namespace keel::compress {

namespace {

// ---------------------------------------------------------------------------
// RFC 1951 static tables
// ---------------------------------------------------------------------------
constexpr i32 kExtraLengthBits[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};

constexpr i32 kLengthBase[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};

constexpr i32 kExtraDistBits[30] = {
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

constexpr i32 kDistBase[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
    193,  257,  385,  513,  769,  1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};

constexpr i32 kCodeLengthOrder[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
};

constexpr u16 bit_reverse(u16 val, i32 len) noexcept {
    u16 res = 0u;
    for (i32 i = 0; i < len; ++i) {
        res = as<u16>((res << 1u) | ((val >> i) & 1u));
    }
    return res;
}

// ---------------------------------------------------------------------------
// Fast 64-bit BitReader for Inflate
// ---------------------------------------------------------------------------
class BitReader {
public:
    BitReader(const u8* src, usize len) noexcept : m_data(src), m_len(len) {}

    void refill() noexcept {
        while (m_bit_count <= 56 && m_pos < m_len) {
            m_bit_buf |= as<u64>(m_data[m_pos++]) << as<u32>(m_bit_count);
            m_bit_count += 8;
        }
    }

    [[nodiscard]] bool read_bits(i32 n, u32& out) noexcept {
        KEEL_ASSERT(n >= 0 && n <= 24);
        if (m_bit_count < n) {
            refill();
            if (m_bit_count < n) [[unlikely]] {
                return false;
            }
        }
        out = (n == 0) ? 0u : as<u32>(m_bit_buf & ((u64{1u} << as<u32>(n)) - 1u));
        m_bit_buf >>= as<u32>(n);
        m_bit_count -= n;
        return true;
    }

    [[nodiscard]] u64 peek_bits() noexcept {
        if (m_bit_count < 15) refill();
        return m_bit_buf;
    }

    [[nodiscard]] i32 available_bits() const noexcept { return m_bit_count; }

    void consume_bits(i32 n) noexcept {
        m_bit_buf >>= as<u32>(n);
        m_bit_count -= n;
    }

    void align_to_byte() noexcept {
        const i32 discard = m_bit_count & 7;
        m_bit_buf >>= as<u32>(discard);
        m_bit_count -= discard;
    }

    // Rewinds unused whole bytes from the 64-bit buffer back to m_pos.
    void sync_byte_pos() noexcept {
        const i32 whole_bytes = m_bit_count / 8;
        m_pos -= as<usize>(whole_bytes);
        m_bit_buf = 0u;
        m_bit_count = 0;
    }

    [[nodiscard]] bool read_u16_le(u16& out) noexcept {
        align_to_byte();
        sync_byte_pos();
        if (m_len - m_pos < 2u) [[unlikely]] {
            return false;
        }
        out = as<u16>(as<u16>(m_data[m_pos]) | (as<u16>(m_data[m_pos + 1u]) << 8u));
        m_pos += 2u;
        return true;
    }

    [[nodiscard]] const u8* current_ptr() const noexcept { return m_data + m_pos; }
    [[nodiscard]] usize remaining_bytes() const noexcept { return (m_pos <= m_len) ? (m_len - m_pos) : 0u; }
    [[nodiscard]] usize consumed_bytes() const noexcept {
        return m_pos - as<usize>(m_bit_count / 8);
    }

    void skip_bytes(usize count) noexcept {
        KEEL_ASSERT(m_bit_count == 0 && count <= remaining_bytes());
        m_pos += count;
    }

private:
    const u8* m_data = nullptr;
    usize m_len = 0u;
    usize m_pos = 0u;
    u64 m_bit_buf = 0u;
    i32 m_bit_count = 0;
};

// ---------------------------------------------------------------------------
// 2-level Fast Table-Driven Huffman Decoder (9-bit primary LUT + subtables)
// ---------------------------------------------------------------------------
class FastHuffman {
public:
    static constexpr i32 kMaxBits = 15;
    static constexpr i32 kPrimaryBits = 9;
    static constexpr usize kPrimarySize = usize{1u} << as<u32>(kPrimaryBits);
    static constexpr u64 kPrimaryMask = kPrimarySize - 1u;

    // Entry encoding:
    //   bits 0..7   : kind (0 = direct symbol, 1 = subtable, 0xFF = invalid)
    //   bits 8..15  : code_len (for kind=0) or subtable_bits (for kind=1)
    //   bits 16..31 : symbol (for kind=0) or subtable_offset (for kind=1)
    static constexpr u32 kInvalidEntry = 0xFFu;

    explicit FastHuffman(Arena& scratch) : m_sub(scratch, 512u) {}

    [[nodiscard]] ErrorCode build(const u8* lens, i32 count, bool allow_empty = false) {
        for (usize i = 0u; i < kPrimarySize; ++i) m_primary[i] = kInvalidEntry;
        m_sub.clear();
        m_empty = false;

        i32 bl_count[kMaxBits + 1] = {};
        i32 max_len = 0;
        for (i32 i = 0; i < count; ++i) {
            const i32 len = as<i32>(lens[i]);
            if (len > kMaxBits) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
            if (len > 0) {
                ++bl_count[len];
                if (len > max_len) max_len = len;
            }
        }
        if (max_len == 0) {
            m_empty = true;
            return allow_empty ? ErrorCode::Ok : ErrorCode::InvalidData;
        }

        // Reject over-subscribed code length sets (RFC 1951 §3.2.2)
        i32 left = 1;
        for (i32 bits = 1; bits <= max_len; ++bits) {
            left <<= 1;
            left -= bl_count[bits];
            if (left < 0) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
        }

        u16 next_code[kMaxBits + 1] = {};
        u16 code = 0u;
        for (i32 bits = 1; bits <= max_len; ++bits) {
            code = as<u16>((code + as<u16>(bl_count[bits - 1])) << 1u);
            next_code[bits] = code;
        }

        // Precompute canonical codes and allocate subtables for codes > kPrimaryBits.
        u16 sym_codes[320] = {};
        u8 sub_max_bits[kPrimarySize] = {};
        for (i32 i = 0; i < count; ++i) {
            const i32 len = as<i32>(lens[i]);
            if (len == 0) continue;
            const u16 c = next_code[len]++;
            const u16 rev = bit_reverse(c, len);
            sym_codes[i] = rev;
            if (len > kPrimaryBits) {
                const usize prefix = as<usize>(rev & kPrimaryMask);
                const u8 extra = as<u8>(len - kPrimaryBits);
                if (extra > sub_max_bits[prefix]) sub_max_bits[prefix] = extra;
            }
        }

        for (usize p = 0u; p < kPrimarySize; ++p) {
            if (sub_max_bits[p] > 0u) {
                const usize sub_off = m_sub.size();
                const usize sub_sz = usize{1u} << as<u32>(sub_max_bits[p]);
                for (usize k = 0u; k < sub_sz; ++k) m_sub.push_back(kInvalidEntry);
                m_primary[p] = (as<u32>(sub_off) << 16u) | (as<u32>(sub_max_bits[p]) << 8u) | 1u;
            }
        }

        for (i32 i = 0; i < count; ++i) {
            const i32 len = as<i32>(lens[i]);
            if (len == 0) continue;
            const u16 rev = sym_codes[i];
            if (len <= kPrimaryBits) {
                const u32 entry = (as<u32>(i) << 16u) | (as<u32>(len) << 8u);
                const usize step = usize{1u} << as<u32>(len);
                for (usize idx = as<usize>(rev); idx < kPrimarySize; idx += step) {
                    if (m_primary[idx] != kInvalidEntry) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }
                    m_primary[idx] = entry;
                }
            } else {
                const usize prefix = as<usize>(rev & kPrimaryMask);
                const u32 pentry = m_primary[prefix];
                const usize sub_off = as<usize>(pentry >> 16u);
                const i32 sub_bits = as<i32>((pentry >> 8u) & 0xFFu);
                const usize sub_sz = usize{1u} << as<u32>(sub_bits);
                const i32 extra = len - kPrimaryBits;
                const u32 entry = (as<u32>(i) << 16u) | (as<u32>(extra) << 8u);
                const usize step = usize{1u} << as<u32>(extra);
                for (usize idx = as<usize>(rev >> as<u32>(kPrimaryBits)); idx < sub_sz; idx += step) {
                    if (m_sub[sub_off + idx] != kInvalidEntry) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }
                    m_sub[sub_off + idx] = entry;
                }
            }
        }
        return ErrorCode::Ok;
    }

    [[nodiscard]] ErrorCode decode(BitReader& br, i32& sym_out) const noexcept {
        if (m_empty) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        const u64 bits = br.peek_bits();
        const i32 avail = br.available_bits();
        if (avail == 0) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        const u32 entry = m_primary[as<usize>(bits & kPrimaryMask)];
        const u32 kind = entry & 0xFFu;
        if (kind == 0u) [[likely]] {
            const i32 clen = as<i32>((entry >> 8u) & 0xFFu);
            if (clen > avail) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            br.consume_bits(clen);
            sym_out = as<i32>(entry >> 16u);
            return ErrorCode::Ok;
        }
        if (kind == 1u) {
            if (avail <= kPrimaryBits) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            const usize sub_off = as<usize>(entry >> 16u);
            const i32 sub_bits = as<i32>((entry >> 8u) & 0xFFu);
            const u64 sub_mask = (u64{1u} << as<u32>(sub_bits)) - 1u;
            const u64 sub_val = (bits >> as<u32>(kPrimaryBits)) & sub_mask;
            const u32 sentry = m_sub[sub_off + as<usize>(sub_val)];
            if ((sentry & 0xFFu) != 0u) [[unlikely]] {
                const i32 rem_avail = avail - kPrimaryBits;
                if (rem_avail < sub_bits) {
                    const u64 rmask = (u64{1u} << as<u32>(rem_avail)) - 1u;
                    const usize sub_sz = usize{1u} << as<u32>(sub_bits);
                    const usize step = usize{1u} << as<u32>(rem_avail);
                    for (usize idx = as<usize>(sub_val & rmask); idx < sub_sz; idx += step) {
                        if ((m_sub[sub_off + idx] & 0xFFu) == 0u) {
                            return ErrorCode::EndOfFile;
                        }
                    }
                }
                return ErrorCode::InvalidData;
            }
            const i32 total_len = kPrimaryBits + as<i32>((sentry >> 8u) & 0xFFu);
            if (total_len > avail) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            br.consume_bits(total_len);
            sym_out = as<i32>(sentry >> 16u);
            return ErrorCode::Ok;
        }
        // Distinguish truncated EOF (partial valid prefix) vs invalid code
        if (avail < kPrimaryBits) {
            // Check whether any code starting with the remaining `avail` bits exists
            const u64 mask = (u64{1u} << as<u32>(avail)) - 1u;
            const u64 prefix = bits & mask;
            const usize step = usize{1u} << as<u32>(avail);
            for (usize idx = as<usize>(prefix); idx < kPrimarySize; idx += step) {
                if (m_primary[idx] != kInvalidEntry) {
                    return ErrorCode::EndOfFile;
                }
            }
        }
        return ErrorCode::InvalidData;
    }

private:
    u32 m_primary[kPrimarySize] = {};
    ArenaArray<u32> m_sub;
    bool m_empty = true;
};

void build_fixed_trees(FastHuffman& lit_tree, FastHuffman& dist_tree) {
    u8 lit_lens[288];
    for (i32 i = 0; i <= 143; ++i) lit_lens[i] = 8u;
    for (i32 i = 144; i <= 255; ++i) lit_lens[i] = 9u;
    for (i32 i = 256; i <= 279; ++i) lit_lens[i] = 7u;
    for (i32 i = 280; i <= 287; ++i) lit_lens[i] = 8u;
    [[maybe_unused]] const ErrorCode ec1 = lit_tree.build(lit_lens, 288);
    KEEL_ASSERT(ec1 == ErrorCode::Ok);

    u8 dist_lens[32];
    for (i32 i = 0; i < 32; ++i) dist_lens[i] = 5u;
    [[maybe_unused]] const ErrorCode ec2 = dist_tree.build(dist_lens, 32);
    KEEL_ASSERT(ec2 == ErrorCode::Ok);
}

[[nodiscard]] Result<Array<u8>> inflate_raw_impl(ArrayRef<u8> src, const InflateOptions& opts, usize* out_consumed) {
    Allocator* dst_alloc = opts.allocator ? opts.allocator : default_allocator();
    Array<u8> out(dst_alloc);

    if (opts.expected_size_hint > 0u) {
        constexpr usize kMaxInitialReserve = 16ULL * 1024u * 1024u;
        usize reserve_cap = keel::min(opts.expected_size_hint, kMaxInitialReserve);
        if (opts.max_output_bytes > 0u) {
            reserve_cap = keel::min(reserve_cap, opts.max_output_bytes);
        }
        out.reserve(reserve_cap);
    }

    auto exceeds_cap = [&](usize add_bytes) noexcept -> bool {
        if (opts.max_output_bytes == 0u) return false;
        return add_bytes > opts.max_output_bytes || out.size() > (opts.max_output_bytes - add_bytes);
    };

    ArenaTemp scratch = get_scratch(dst_alloc);
    FastHuffman lit_tree(scratch.arena());
    FastHuffman dist_tree(scratch.arena());
    FastHuffman cl_tree(scratch.arena());

    BitReader br(src.data(), src.size());
    bool bfinal = false;

    while (!bfinal) {
        u32 bfinal_bit = 0u;
        u32 btype = 0u;
        if (!br.read_bits(1, bfinal_bit) || !br.read_bits(2, btype)) [[unlikely]] {
            return ErrorCode::EndOfFile;
        }
        bfinal = (bfinal_bit != 0u);

        if (btype == 0u) {
            u16 blen = 0u;
            u16 nlen = 0u;
            if (!br.read_u16_le(blen) || !br.read_u16_le(nlen)) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            if (as<u16>(blen ^ 0xFFFFu) != nlen) [[unlikely]] {
                return ErrorCode::InvalidData;
            }
            if (br.remaining_bytes() < blen) [[unlikely]] {
                return ErrorCode::EndOfFile;
            }
            if (exceeds_cap(blen)) [[unlikely]] {
                return ErrorCode::OutOfRange;
            }
            if (blen > 0u) {
                out.append(ArrayRef<u8>(br.current_ptr(), blen));
                br.skip_bytes(blen);
            }
        } else if (btype == 1u || btype == 2u) {
            if (btype == 1u) {
                build_fixed_trees(lit_tree, dist_tree);
            } else {
                u32 hlit_raw = 0u;
                u32 hdist_raw = 0u;
                u32 hclen_raw = 0u;
                if (!br.read_bits(5, hlit_raw) || !br.read_bits(5, hdist_raw) || !br.read_bits(4, hclen_raw))
                    [[unlikely]] {
                    return ErrorCode::EndOfFile;
                }
                const i32 hlit = as<i32>(hlit_raw) + 257;
                const i32 hdist = as<i32>(hdist_raw) + 1;
                const i32 hclen = as<i32>(hclen_raw) + 4;
                if (hlit > 286 || hdist > 30) [[unlikely]] {
                    return ErrorCode::InvalidData;
                }

                u8 cl_code_lens[19] = {};
                for (i32 i = 0; i < hclen; ++i) {
                    u32 cl_val = 0u;
                    if (!br.read_bits(3, cl_val)) [[unlikely]] {
                        return ErrorCode::EndOfFile;
                    }
                    cl_code_lens[kCodeLengthOrder[i]] = as<u8>(cl_val);
                }

                const ErrorCode cl_ec = cl_tree.build(cl_code_lens, 19);
                if (cl_ec != ErrorCode::Ok) [[unlikely]] {
                    return cl_ec;
                }

                const i32 total_codes = hlit + hdist;
                u8 all_lens[320] = {};
                i32 idx = 0;
                while (idx < total_codes) {
                    i32 sym = 0;
                    const ErrorCode dec_ec = cl_tree.decode(br, sym);
                    if (dec_ec != ErrorCode::Ok) [[unlikely]] {
                        return dec_ec;
                    }
                    if (sym < 16) {
                        all_lens[idx++] = as<u8>(sym);
                    } else if (sym == 16) {
                        if (idx == 0) [[unlikely]] {
                            return ErrorCode::InvalidData;
                        }
                        u32 rep_extra = 0u;
                        if (!br.read_bits(2, rep_extra)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        const i32 rep = as<i32>(rep_extra) + 3;
                        if (idx + rep > total_codes) [[unlikely]] {
                            return ErrorCode::InvalidData;
                        }
                        const u8 prev = all_lens[idx - 1];
                        for (i32 r = 0; r < rep; ++r) {
                            all_lens[idx++] = prev;
                        }
                    } else if (sym == 17 || sym == 18) {
                        u32 rep_extra = 0u;
                        const i32 extra_bits = (sym == 17) ? 3 : 7;
                        const i32 base_rep = (sym == 17) ? 3 : 11;
                        if (!br.read_bits(extra_bits, rep_extra)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        const i32 rep = as<i32>(rep_extra) + base_rep;
                        if (idx + rep > total_codes) [[unlikely]] {
                            return ErrorCode::InvalidData;
                        }
                        for (i32 r = 0; r < rep; ++r) {
                            all_lens[idx++] = 0u;
                        }
                    } else {
                        return ErrorCode::InvalidData;
                    }
                }

                if (all_lens[256] == 0u) [[unlikely]] {
                    return ErrorCode::InvalidData;
                }

                const ErrorCode lit_ec = lit_tree.build(all_lens, hlit);
                if (lit_ec != ErrorCode::Ok) [[unlikely]] {
                    return lit_ec;
                }
                const ErrorCode dist_ec = dist_tree.build(all_lens + hlit, hdist, true);
                if (dist_ec != ErrorCode::Ok) [[unlikely]] {
                    return dist_ec;
                }
            }

            while (true) {
                i32 sym = 0;
                const ErrorCode sym_ec = lit_tree.decode(br, sym);
                if (sym_ec != ErrorCode::Ok) [[unlikely]] {
                    return sym_ec;
                }

                if (sym < 256) [[likely]] {
                    if (exceeds_cap(1u)) [[unlikely]] {
                        return ErrorCode::OutOfRange;
                    }
                    out.push_back(as<u8>(sym));
                } else if (sym == 256) {
                    break;
                } else if (sym <= 285) {
                    const i32 len_idx = sym - 257;
                    usize length = as<usize>(kLengthBase[len_idx]);
                    const i32 extra_bits = kExtraLengthBits[len_idx];
                    if (extra_bits > 0) {
                        u32 extra_val = 0u;
                        if (!br.read_bits(extra_bits, extra_val)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        length += as<usize>(extra_val);
                    }

                    i32 dist_sym = 0;
                    const ErrorCode dist_ec = dist_tree.decode(br, dist_sym);
                    if (dist_ec != ErrorCode::Ok) [[unlikely]] {
                        return dist_ec;
                    }
                    if (dist_sym < 0 || dist_sym >= 30) [[unlikely]] {
                        return ErrorCode::InvalidData;
                    }

                    usize dist = as<usize>(kDistBase[dist_sym]);
                    const i32 extra_dist_bits = kExtraDistBits[dist_sym];
                    if (extra_dist_bits > 0) {
                        u32 extra_val = 0u;
                        if (!br.read_bits(extra_dist_bits, extra_val)) [[unlikely]] {
                            return ErrorCode::EndOfFile;
                        }
                        dist += as<usize>(extra_val);
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
                    } else if (dist == 1u) {
                        mem_set(dst, *copy_src, length);
                    } else {
                        for (usize k = 0u; k < length; ++k) {
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

// ---------------------------------------------------------------------------
// Deflate BitWriter + Fixed & Dynamic Huffman Encoder
// ---------------------------------------------------------------------------
class BitWriter {
public:
    BitWriter(Array<u8>& dst, u32& bit_buf, i32& bit_count) noexcept
        : m_bytes(dst), m_bit_buf(bit_buf), m_bit_count(bit_count) {}

    void write_bits(u32 val, i32 n) {
        KEEL_ASSERT(n >= 0 && n <= 24);
        m_bit_buf |= (val << as<u32>(m_bit_count));
        m_bit_count += n;
        while (m_bit_count >= 8) {
            m_bytes.push_back(as<u8>(m_bit_buf & 0xFFu));
            m_bit_buf >>= 8u;
            m_bit_count -= 8;
        }
    }

    void align_to_byte() {
        if (m_bit_count > 0) {
            m_bytes.push_back(as<u8>(m_bit_buf & 0xFFu));
            m_bit_buf = 0u;
            m_bit_count = 0;
        }
    }

    void write_bytes(const u8* data, usize len) {
        align_to_byte();
        if (len > 0u) {
            m_bytes.append(ArrayRef<u8>(data, len));
        }
    }

    [[nodiscard]] i32 pending_bits() const noexcept { return m_bit_count; }

private:
    Array<u8>& m_bytes;
    u32& m_bit_buf;
    i32& m_bit_count;
};

struct HuffCode {
    u16 bits = 0u;
    u8 len = 0u;
};

struct FixedLitTable {
    HuffCode codes[288]{};
    u8 dist_codes[30]{};
};

consteval FixedLitTable make_fixed_lit_table() noexcept {
    FixedLitTable tbl{};
    for (i32 sym = 0; sym < 288; ++sym) {
        if (sym <= 143) {
            tbl.codes[sym] = {bit_reverse(as<u16>(0x30 + sym), 8), 8u};
        } else if (sym <= 255) {
            tbl.codes[sym] = {bit_reverse(as<u16>(0x190 + (sym - 144)), 9), 9u};
        } else if (sym <= 279) {
            tbl.codes[sym] = {bit_reverse(as<u16>(sym - 256), 7), 7u};
        } else {
            tbl.codes[sym] = {bit_reverse(as<u16>(0xC0 + (sym - 280)), 8), 8u};
        }
    }
    for (i32 d = 0; d < 30; ++d) {
        tbl.dist_codes[d] = as<u8>(bit_reverse(as<u16>(d), 5));
    }
    return tbl;
}

constexpr FixedLitTable kFixedLitTable = make_fixed_lit_table();

// Fast O(1) lookup tables for length (3..258) -> len_idx (0..28) and small distances
struct LenDistLut {
    u8 len_idx[259]{};
    u8 dist_small[513]{};
};

consteval LenDistLut make_len_dist_lut() noexcept {
    LenDistLut lut{};
    for (i32 l = 3; l <= 258; ++l) {
        i32 idx = 0;
        for (i32 i = 0; i < 29; ++i) {
            if (kLengthBase[i] <= l) idx = i;
            else break;
        }
        lut.len_idx[l] = as<u8>(idx);
    }
    for (i32 d = 1; d <= 512; ++d) {
        i32 idx = 0;
        for (i32 i = 0; i < 30; ++i) {
            if (kDistBase[i] <= d) idx = i;
            else break;
        }
        lut.dist_small[d] = as<u8>(idx);
    }
    return lut;
}

constexpr LenDistLut kLenDistLut = make_len_dist_lut();

inline i32 find_dist_idx(usize dist) noexcept {
    if (dist <= 512u) return as<i32>(kLenDistLut.dist_small[dist]);
    i32 idx = 16;
    for (i32 i = 17; i < 30; ++i) {
        if (as<usize>(kDistBase[i]) <= dist) idx = i;
        else break;
    }
    return idx;
}

// Length-limited canonical Huffman builder (max_bits <= 15)
void build_huffman_lengths(const u32* freqs, i32 num_syms, i32 max_bits, u8* lens_out) noexcept {
    for (i32 i = 0; i < num_syms; ++i) lens_out[i] = 0u;

    struct Node {
        u32 freq;
        i16 sym;    // >= 0 for leaf, -1 for internal
        i16 left;
        i16 right;
    };

    // Max 286 leaves -> max 571 nodes
    Node nodes[576]{};
    i16 heap[288]{};
    i32 heap_sz = 0;
    i32 node_cnt = 0;

    auto heap_less = [&](i16 a, i16 b) noexcept -> bool {
        if (nodes[a].freq != nodes[b].freq) return nodes[a].freq < nodes[b].freq;
        return a < b;
    };
    auto heap_push = [&](i16 idx) noexcept {
        i32 cur = heap_sz++;
        heap[cur] = idx;
        while (cur > 0) {
            const i32 par = (cur - 1) >> 1;
            if (!heap_less(heap[cur], heap[par])) break;
            const i16 tmp = heap[cur];
            heap[cur] = heap[par];
            heap[par] = tmp;
            cur = par;
        }
    };
    auto heap_pop = [&]() noexcept -> i16 {
        const i16 top = heap[0];
        heap[0] = heap[--heap_sz];
        i32 cur = 0;
        while (true) {
            const i32 l = cur * 2 + 1;
            const i32 r = l + 1;
            i32 best = cur;
            if (l < heap_sz && heap_less(heap[l], heap[best])) best = l;
            if (r < heap_sz && heap_less(heap[r], heap[best])) best = r;
            if (best == cur) break;
            const i16 tmp = heap[cur];
            heap[cur] = heap[best];
            heap[best] = tmp;
            cur = best;
        }
        return top;
    };

    for (i32 i = 0; i < num_syms; ++i) {
        if (freqs[i] > 0u) {
            const i16 id = as<i16>(node_cnt++);
            nodes[id] = {freqs[i], as<i16>(i), -1, -1};
            heap_push(id);
        }
    }

    if (heap_sz == 0) return;
    if (heap_sz == 1) {
        lens_out[nodes[heap[0]].sym] = 1u;
        return;
    }

    while (heap_sz > 1) {
        const i16 a = heap_pop();
        const i16 b = heap_pop();
        const i16 p = as<i16>(node_cnt++);
        nodes[p] = {nodes[a].freq + nodes[b].freq, -1, a, b};
        heap_push(p);
    }

    // BFS/stack depth calculation
    i16 stk_node[576]{};
    u8 stk_depth[576]{};
    i32 sp = 0;
    stk_node[sp] = heap[0];
    stk_depth[sp] = 0u;
    ++sp;

    bool needs_limit = false;
    while (sp > 0) {
        --sp;
        const i16 id = stk_node[sp];
        const u8 d = stk_depth[sp];
        if (nodes[id].sym >= 0) {
            if (d > as<u8>(max_bits)) {
                lens_out[nodes[id].sym] = as<u8>(max_bits);
                needs_limit = true;
            } else {
                lens_out[nodes[id].sym] = d;
            }
        } else {
            stk_node[sp] = nodes[id].left;
            stk_depth[sp] = as<u8>(d + 1u);
            ++sp;
            stk_node[sp] = nodes[id].right;
            stk_depth[sp] = as<u8>(d + 1u);
            ++sp;
        }
    }

    if (!needs_limit) return;

    // Enforce exact Kraft equality sum(2^(max_bits - L_i)) == 2^max_bits
    const u32 target = u32{1u} << as<u32>(max_bits);
    u32 kraft = 0u;
    for (i32 i = 0; i < num_syms; ++i) {
        if (lens_out[i] > 0u) kraft += u32{1u} << as<u32>(max_bits - as<i32>(lens_out[i]));
    }

    // Overflow: lengthen symbols with len < max_bits (preferring lower frequencies)
    while (kraft > target) {
        i32 best_sym = -1;
        for (i32 i = 0; i < num_syms; ++i) {
            if (lens_out[i] > 0u && lens_out[i] < as<u8>(max_bits)) {
                if (best_sym < 0 || lens_out[i] > lens_out[best_sym] ||
                    (lens_out[i] == lens_out[best_sym] && freqs[i] < freqs[best_sym])) {
                    best_sym = i;
                }
            }
        }
        if (best_sym < 0) break;
        const u32 delta = u32{1u} << as<u32>(max_bits - as<i32>(lens_out[best_sym]) - 1);
        ++lens_out[best_sym];
        kraft -= delta;
    }

    // Underflow: shorten symbols where it fits (preferring higher frequencies)
    while (kraft < target) {
        i32 best_sym = -1;
        for (i32 i = 0; i < num_syms; ++i) {
            if (lens_out[i] > 1u) {
                const u32 delta = u32{1u} << as<u32>(max_bits - as<i32>(lens_out[i]));
                if (kraft + delta <= target) {
                    if (best_sym < 0 || freqs[i] > freqs[best_sym]) {
                        best_sym = i;
                    }
                }
            }
        }
        if (best_sym < 0) break;
        const u32 delta = u32{1u} << as<u32>(max_bits - as<i32>(lens_out[best_sym]));
        --lens_out[best_sym];
        kraft += delta;
    }
}

void build_canonical_codes(const u8* lens, i32 count, HuffCode* codes_out) noexcept {
    i32 bl_count[16] = {};
    for (i32 i = 0; i < count; ++i) {
        codes_out[i] = {0u, lens[i]};
        if (lens[i] > 0u) ++bl_count[lens[i]];
    }
    u16 next_code[16] = {};
    u16 code = 0u;
    for (i32 bits = 1; bits <= 15; ++bits) {
        code = as<u16>((code + as<u16>(bl_count[bits - 1])) << 1u);
        next_code[bits] = code;
    }
    for (i32 i = 0; i < count; ++i) {
        const i32 len = as<i32>(lens[i]);
        if (len > 0) {
            codes_out[i].bits = bit_reverse(next_code[len]++, len);
        }
    }
}

struct Token {
    u16 lit_or_len; // 0..255 literal when dist==0; 3..258 length when dist>0
    u16 dist;       // 0 for literal, 1..32768 for match
};

struct RleCode {
    u8 sym;
    u8 extra;
    u8 extra_bits;
};

void rle_encode_code_lengths(const u8* lens, i32 total, RleCode* out, i32& out_cnt, u32 cl_freqs[19]) noexcept {
    for (i32 i = 0; i < 19; ++i) cl_freqs[i] = 0u;
    out_cnt = 0;
    i32 i = 0;
    while (i < total) {
        const u8 cur = lens[i];
        i32 run = 1;
        while (i + run < total && lens[i + run] == cur) ++run;
        const i32 advance = run;

        if (cur == 0u) {
            while (run >= 11) {
                const i32 take = (run > 138) ? 138 : run;
                out[out_cnt++] = {18u, as<u8>(take - 11), 7u};
                ++cl_freqs[18];
                run -= take;
            }
            if (run >= 3) {
                out[out_cnt++] = {17u, as<u8>(run - 3), 3u};
                ++cl_freqs[17];
                run = 0;
            }
            while (run-- > 0) {
                out[out_cnt++] = {0u, 0u, 0u};
                ++cl_freqs[0];
            }
        } else {
            out[out_cnt++] = {cur, 0u, 0u};
            ++cl_freqs[cur];
            --run;
            while (run >= 3) {
                const i32 take = (run > 6) ? 6 : run;
                out[out_cnt++] = {16u, as<u8>(take - 3), 2u};
                ++cl_freqs[16];
                run -= take;
            }
            while (run-- > 0) {
                out[out_cnt++] = {cur, 0u, 0u};
                ++cl_freqs[cur];
            }
        }
        i += advance;
    }
}

void write_stored_blocks(BitWriter& bw, const u8* data, usize len, bool is_final_stream) {
    usize pos = 0u;
    while (pos < len || len == 0u) {
        const usize chunk = keel::min<usize>(len - pos, 65535u);
        const bool is_last = is_final_stream && (pos + chunk >= len);
        bw.write_bits(is_last ? 1u : 0u, 1);
        bw.write_bits(0u, 2); // BTYPE = 00
        bw.align_to_byte();
        const u16 blen = as<u16>(chunk);
        const u16 nlen = as<u16>(blen ^ 0xFFFFu);
        bw.write_bits(blen, 16);
        bw.write_bits(nlen, 16);
        if (chunk > 0u) {
            bw.write_bytes(data + pos, chunk);
        }
        pos += chunk;
        if (pos >= len) break;
    }
}

// Emits one Deflate block for `data[block_start .. block_start + block_len]`,
// using prior history `data[0 .. block_start]` (up to 32 KiB) for LZ77 matching.
void deflate_block(BitWriter& bw, const u8* data, usize block_start, usize block_len,
                   i32 level, bool is_final, Allocator* scratch_fallback) {
    if (level <= 0 || block_len == 0u) {
        write_stored_blocks(bw, data + block_start, block_len, is_final);
        return;
    }

    constexpr usize kHashSize = 32768u;
    constexpr usize kWindowSize = 32768u;
    constexpr usize kMinMatch = 3u;
    constexpr usize kMaxMatch = 258u;
    const usize total_end = block_start + block_len;

    ArenaTemp scratch = get_scratch(scratch_fallback);
    usize* head = scratch.arena().alloc_array<usize>(kHashSize);
    usize* prev = scratch.arena().alloc_array<usize>(kWindowSize);
    Token* tokens = scratch.arena().alloc_array<Token>(block_len);
    mem_set(head, 0xFF, kHashSize * sizeof(usize));
    mem_set(prev, 0xFF, kWindowSize * sizeof(usize));

    auto hash3 = [](const u8* p) noexcept -> usize {
        return ((as<usize>(p[0]) << 10u) ^ (as<usize>(p[1]) << 5u) ^ as<usize>(p[2])) &
               (kHashSize - 1u);
    };

    // Prime hash table with prior sliding window history
    const usize hist_begin = (block_start > kWindowSize) ? (block_start - kWindowSize) : 0u;
    for (usize p = hist_begin; p < block_start; ++p) {
        if (p + kMinMatch <= total_end) {
            const usize h = hash3(data + p);
            prev[p & (kWindowSize - 1u)] = head[h];
            head[h] = p;
        }
    }

    const i32 max_chain = (level <= 2) ? 4 : ((level <= 4) ? 12 : ((level <= 6) ? 32 : ((level <= 8) ? 96 : 256)));
    const usize nice_len = (level <= 3) ? 16u : ((level <= 6) ? 64u : ((level <= 8) ? 128u : 258u));
    const bool use_lazy = (level >= 4);
    const usize max_lazy = (level <= 6) ? 16u : ((level <= 8) ? 64u : 258u);

    auto find_match = [&](usize pos, usize& out_len, usize& out_dist) noexcept {
        out_len = 0u;
        out_dist = 0u;
        if (pos + kMinMatch > total_end) return;

        const usize h = hash3(data + pos);
        usize match_pos = head[h];
        prev[pos & (kWindowSize - 1u)] = match_pos;
        head[h] = pos;

        i32 chain_limit = max_chain;
        const usize max_len_possible = keel::min<usize>(total_end - pos, kMaxMatch);
        while (match_pos != kInvalidIndex && (pos - match_pos) <= kWindowSize && chain_limit-- > 0) {
            const usize cur_dist = pos - match_pos;
            if (data[pos + out_len] == data[match_pos + out_len] && data[pos] == data[match_pos]) {
                usize mlen = 0u;
                while (mlen < max_len_possible && data[pos + mlen] == data[match_pos + mlen]) {
                    ++mlen;
                }
                if (mlen > out_len) {
                    out_len = mlen;
                    out_dist = cur_dist;
                    if (out_len >= nice_len || out_len >= max_len_possible) break;
                }
            }
            match_pos = prev[match_pos & (kWindowSize - 1u)];
        }
    };

    u32 lit_freqs[286] = {};
    u32 dist_freqs[30] = {};
    usize num_tokens = 0u;

    usize pos = block_start;
    while (pos < total_end) {
        usize best_len = 0u;
        usize best_dist = 0u;
        find_match(pos, best_len, best_dist);

        // Lazy matching: check if pos+1 yields a strictly better match
        if (use_lazy && best_len >= kMinMatch && best_len < max_lazy && pos + 1u < total_end) {
            usize next_len = 0u;
            usize next_dist = 0u;
            find_match(pos + 1u, next_len, next_dist);
            if (next_len > best_len + 1u || (level >= 7 && next_len > best_len)) {
                // Emit literal at pos, adopt next match
                const u8 lit = data[pos];
                tokens[num_tokens++] = {as<u16>(lit), 0u};
                ++lit_freqs[lit];
                ++pos;
                best_len = next_len;
                best_dist = next_dist;
            } else {
                // We already inserted pos+1 into hash; advance past match carefully below
                const i32 lidx = as<i32>(kLenDistLut.len_idx[best_len]);
                const i32 didx = find_dist_idx(best_dist);
                tokens[num_tokens++] = {as<u16>(best_len), as<u16>(best_dist)};
                ++lit_freqs[257 + lidx];
                ++dist_freqs[didx];
                for (usize k = 2u; k < best_len; ++k) {
                    if (pos + k + kMinMatch <= total_end) {
                        const usize h = hash3(data + pos + k);
                        prev[(pos + k) & (kWindowSize - 1u)] = head[h];
                        head[h] = pos + k;
                    }
                }
                pos += best_len;
                continue;
            }
        }

        if (best_len >= kMinMatch) {
            const i32 lidx = as<i32>(kLenDistLut.len_idx[best_len]);
            const i32 didx = find_dist_idx(best_dist);
            tokens[num_tokens++] = {as<u16>(best_len), as<u16>(best_dist)};
            ++lit_freqs[257 + lidx];
            ++dist_freqs[didx];
            for (usize k = 1u; k < best_len; ++k) {
                if (pos + k + kMinMatch <= total_end) {
                    const usize h = hash3(data + pos + k);
                    prev[(pos + k) & (kWindowSize - 1u)] = head[h];
                    head[h] = pos + k;
                }
            }
            pos += best_len;
        } else {
            const u8 lit = data[pos++];
            tokens[num_tokens++] = {as<u16>(lit), 0u};
            ++lit_freqs[lit];
        }
    }
    ++lit_freqs[256]; // EOB

    // Build optimal dynamic Huffman tables
    u8 lit_lens[286] = {};
    u8 dist_lens[30] = {};
    build_huffman_lengths(lit_freqs, 286, 15, lit_lens);
    build_huffman_lengths(dist_freqs, 30, 15, dist_lens);

    // Ensure at least 1 distance code length entry for valid hdist >= 1
    i32 hlit = 286;
    while (hlit > 257 && lit_lens[hlit - 1] == 0u) --hlit;
    i32 hdist = 30;
    while (hdist > 1 && dist_lens[hdist - 1] == 0u) --hdist;

    u8 combined_lens[316] = {};
    for (i32 i = 0; i < hlit; ++i) combined_lens[i] = lit_lens[i];
    for (i32 i = 0; i < hdist; ++i) combined_lens[hlit + i] = dist_lens[i];

    RleCode rle[320]{};
    i32 rle_cnt = 0;
    u32 cl_freqs[19] = {};
    rle_encode_code_lengths(combined_lens, hlit + hdist, rle, rle_cnt, cl_freqs);

    u8 cl_lens[19] = {};
    build_huffman_lengths(cl_freqs, 19, 7, cl_lens);
    i32 hclen = 19;
    while (hclen > 4 && cl_lens[kCodeLengthOrder[hclen - 1]] == 0u) --hclen;

    // Exact bit cost comparison: Dynamic vs Fixed vs Stored
    u64 dyn_bits = 3u + 5u + 5u + 4u + as<u64>(hclen) * 3u;
    for (i32 i = 0; i < rle_cnt; ++i) {
        dyn_bits += as<u64>(cl_lens[rle[i].sym]) + as<u64>(rle[i].extra_bits);
    }
    u64 fix_bits = 3u;

    for (i32 i = 0; i < 286; ++i) {
        if (lit_freqs[i] > 0u) {
            const u64 extra = (i >= 257) ? as<u64>(kExtraLengthBits[i - 257]) : 0u;
            dyn_bits += as<u64>(lit_freqs[i]) * (as<u64>(lit_lens[i]) + extra);
            fix_bits += as<u64>(lit_freqs[i]) * (as<u64>(kFixedLitTable.codes[i].len) + extra);
        }
    }
    for (i32 i = 0; i < 30; ++i) {
        if (dist_freqs[i] > 0u) {
            const u64 extra = as<u64>(kExtraDistBits[i]);
            dyn_bits += as<u64>(dist_freqs[i]) * (as<u64>(dist_lens[i]) + extra);
            fix_bits += as<u64>(dist_freqs[i]) * (5u + extra);
        }
    }

    const usize num_stored_chunks = (block_len + 65534u) / 65535u;
    const u64 pad_bits = as<u64>((8 - ((bw.pending_bits() + 3) & 7)) & 7);
    const u64 stored_bits = pad_bits + as<u64>(num_stored_chunks) * 40u + as<u64>(block_len) * 8u;

    if (stored_bits <= fix_bits && stored_bits <= dyn_bits) {
        write_stored_blocks(bw, data + block_start, block_len, is_final);
        return;
    }

    if (dyn_bits < fix_bits) {
        HuffCode cl_codes[19]{};
        HuffCode lit_codes[286]{};
        HuffCode dist_codes[30]{};
        build_canonical_codes(cl_lens, 19, cl_codes);
        build_canonical_codes(lit_lens, hlit, lit_codes);
        build_canonical_codes(dist_lens, hdist, dist_codes);

        bw.write_bits(is_final ? 1u : 0u, 1);
        bw.write_bits(2u, 2); // BTYPE = 10 (Dynamic Huffman)
        bw.write_bits(as<u32>(hlit - 257), 5);
        bw.write_bits(as<u32>(hdist - 1), 5);
        bw.write_bits(as<u32>(hclen - 4), 4);
        for (i32 i = 0; i < hclen; ++i) {
            bw.write_bits(cl_lens[kCodeLengthOrder[i]], 3);
        }
        for (i32 i = 0; i < rle_cnt; ++i) {
            const HuffCode cc = cl_codes[rle[i].sym];
            bw.write_bits(cc.bits, cc.len);
            if (rle[i].extra_bits > 0u) {
                bw.write_bits(rle[i].extra, as<i32>(rle[i].extra_bits));
            }
        }
        for (usize t = 0u; t < num_tokens; ++t) {
            const Token tok = tokens[t];
            if (tok.dist == 0u) {
                const HuffCode lc = lit_codes[tok.lit_or_len];
                bw.write_bits(lc.bits, lc.len);
            } else {
                const i32 lidx = as<i32>(kLenDistLut.len_idx[tok.lit_or_len]);
                const HuffCode lc = lit_codes[257 + lidx];
                bw.write_bits(lc.bits, lc.len);
                const i32 el = kExtraLengthBits[lidx];
                if (el > 0) bw.write_bits(as<u32>(tok.lit_or_len - as<u16>(kLengthBase[lidx])), el);

                const i32 didx = find_dist_idx(tok.dist);
                const HuffCode dc = dist_codes[didx];
                bw.write_bits(dc.bits, dc.len);
                const i32 ed = kExtraDistBits[didx];
                if (ed > 0) bw.write_bits(as<u32>(tok.dist - as<u16>(kDistBase[didx])), ed);
            }
        }
        const HuffCode eob = lit_codes[256];
        bw.write_bits(eob.bits, eob.len);
    } else {
        bw.write_bits(is_final ? 1u : 0u, 1);
        bw.write_bits(1u, 2); // BTYPE = 01 (Fixed Huffman)
        for (usize t = 0u; t < num_tokens; ++t) {
            const Token tok = tokens[t];
            if (tok.dist == 0u) {
                const HuffCode lc = kFixedLitTable.codes[tok.lit_or_len];
                bw.write_bits(lc.bits, lc.len);
            } else {
                const i32 lidx = as<i32>(kLenDistLut.len_idx[tok.lit_or_len]);
                const HuffCode lc = kFixedLitTable.codes[257 + lidx];
                bw.write_bits(lc.bits, lc.len);
                const i32 el = kExtraLengthBits[lidx];
                if (el > 0) bw.write_bits(as<u32>(tok.lit_or_len - as<u16>(kLengthBase[lidx])), el);

                const i32 didx = find_dist_idx(tok.dist);
                bw.write_bits(kFixedLitTable.dist_codes[didx], 5);
                const i32 ed = kExtraDistBits[didx];
                if (ed > 0) bw.write_bits(as<u32>(tok.dist - as<u16>(kDistBase[didx])), ed);
            }
        }
        const HuffCode eob = kFixedLitTable.codes[256];
        bw.write_bits(eob.bits, eob.len);
    }
}

void deflate_into(Array<u8>& out, ArrayRef<u8> src, i32 level) {
    u32 bit_buf = 0u;
    i32 bit_count = 0;
    BitWriter bw(out, bit_buf, bit_count);

    if (level <= 0 || src.empty()) {
        write_stored_blocks(bw, src.data(), src.size(), true);
        bw.align_to_byte();
        return;
    }

    constexpr usize kBlockBytes = 65536u;
    usize pos = 0u;
    while (pos < src.size()) {
        const usize chunk = keel::min<usize>(src.size() - pos, kBlockBytes);
        const bool is_final = (pos + chunk >= src.size());
        deflate_block(bw, src.data(), pos, chunk, level, is_final, out.allocator());
        pos += chunk;
    }
    bw.align_to_byte();
}

void write_zlib_header(Array<u8>& out, i32 level) {
    const u8 cmf = 0x78u;
    u8 flg = (level <= 0) ? 0x00u : ((level <= 3) ? 0x40u : ((level <= 6) ? 0x80u : 0xC0u));
    const u32 rem = ((as<u32>(cmf) << 8u) + as<u32>(flg)) % 31u;
    if (rem != 0u) {
        flg = as<u8>(flg + (31u - rem));
    }
    out.push_back(cmf);
    out.push_back(flg);
}

void write_gzip_minimal_header(Array<u8>& out, i32 level) {
    out.push_back(0x1Fu);
    out.push_back(0x8Bu);
    out.push_back(0x08u); // CM = deflate
    out.push_back(0x00u); // FLG = 0
    for (usize i = 0u; i < 4u; ++i) out.push_back(0x00u); // MTIME = 0
    out.push_back((level >= 9) ? 0x02u : ((level <= 1) ? 0x04u : 0x00u)); // XFL
    out.push_back(0xFFu); // OS = unknown
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
Result<Array<u8>> inflate_raw(ArrayRef<u8> src, const InflateOptions& opts) {
    return inflate_raw_impl(src, opts, nullptr);
}

Result<Array<u8>> inflate_raw_ex(ArrayRef<u8> src, usize& consumed_out, const InflateOptions& opts) {
    return inflate_raw_impl(src, opts, &consumed_out);
}

Array<u8> deflate_raw(ArrayRef<u8> src, i32 level, Allocator* alloc) {
    Array<u8> out(alloc);
    out.reserve((src.size() / 2u) + 32u);
    deflate_into(out, src, level);
    return out;
}

Result<Array<u8>> zlib_decompress(ArrayRef<u8> src, const InflateOptions& opts) {
    if (src.size() < 6u) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }

    const u8 cmf = src[0];
    const u8 flg = src[1];
    if (((as<u32>(cmf) << 8u) + as<u32>(flg)) % 31u != 0u) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    if ((cmf & 0x0Fu) != 8u || (cmf >> 4u) > 7u) [[unlikely]] {
        return ErrorCode::NotSupported;
    }
    if ((flg & 0x20u) != 0u) [[unlikely]] {
        return ErrorCode::NotSupported;
    }

    usize consumed_deflate = 0u;
    KEEL_TRY_ASSIGN(Array<u8> uncompressed,
                    inflate_raw_impl(src.slice(2u, src.size() - 6u), opts, &consumed_deflate));

    const usize adler_pos = 2u + consumed_deflate;
    if (adler_pos + 4u > src.size()) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }
    const u32 expected_adler = (as<u32>(src[adler_pos]) << 24u) | (as<u32>(src[adler_pos + 1u]) << 16u) |
                               (as<u32>(src[adler_pos + 2u]) << 8u) | as<u32>(src[adler_pos + 3u]);
    const u32 actual_adler = adler32(uncompressed);
    if (expected_adler != actual_adler) [[unlikely]] {
        return ErrorCode::InvalidData;
    }

    return uncompressed;
}

Array<u8> zlib_compress(ArrayRef<u8> src, i32 level, Allocator* alloc) {
    Array<u8> out(alloc);
    out.reserve((src.size() / 2u) + 64u);
    write_zlib_header(out, level);
    deflate_into(out, src, level);

    const u32 adler = adler32(src);
    out.push_back(as<u8>((adler >> 24u) & 0xFFu));
    out.push_back(as<u8>((adler >> 16u) & 0xFFu));
    out.push_back(as<u8>((adler >> 8u) & 0xFFu));
    out.push_back(as<u8>(adler & 0xFFu));
    return out;
}

// ---------------------------------------------------------------------------
// Streaming DeflateStream
// ---------------------------------------------------------------------------
DeflateStream::DeflateStream(StreamFormat fmt, i32 level, Allocator* alloc)
    : m_format(fmt),
      m_level(level),
      m_alloc(alloc ? alloc : default_allocator()),
      m_window(m_alloc),
      m_out(m_alloc) {
    m_window.reserve(98304u);
}

void DeflateStream::flush_block(bool is_final) {
    if (!m_header_written) {
        if (m_format == StreamFormat::Zlib) {
            write_zlib_header(m_out, m_level);
        } else if (m_format == StreamFormat::Gzip) {
            write_gzip_minimal_header(m_out, m_level);
        }
        m_header_written = true;
    }

    const usize pending = m_window.size() - m_hist_len;
    BitWriter bw(m_out, m_bit_buf, m_bit_count);
    deflate_block(bw, m_window.data(), m_hist_len, pending, m_level, is_final, m_alloc);
    if (is_final) {
        bw.align_to_byte();
    }

    // Retain last 32 KiB as sliding window history for subsequent blocks
    constexpr usize kKeep = 32768u;
    if (m_window.size() > kKeep) {
        const usize drop = m_window.size() - kKeep;
        mem_move(m_window.data(), m_window.data() + drop, kKeep);
        m_window.resize(kKeep);
    }
    m_hist_len = m_window.size();
}

void DeflateStream::update(ArrayRef<u8> data) {
    if (m_finished || data.empty()) return;

    m_total_in += as<u64>(data.size());
    if (m_format == StreamFormat::Zlib) {
        m_adler = adler32_update(m_adler, data);
    } else if (m_format == StreamFormat::Gzip) {
        m_crc = crc32_update(m_crc, data);
    }

    constexpr usize kBlockBytes = 65536u;
    usize off = 0u;
    while (off < data.size()) {
        const usize pending = m_window.size() - m_hist_len;
        const usize room = (pending < kBlockBytes) ? (kBlockBytes - pending) : 0u;
        const usize take = keel::min<usize>(data.size() - off, room);
        if (take > 0u) {
            m_window.append(ArrayRef<u8>(data.data() + off, take));
            off += take;
        }
        if ((m_window.size() - m_hist_len) >= kBlockBytes) {
            flush_block(false);
        }
    }
}

Array<u8> DeflateStream::take_output() {
    Array<u8> res(keel::move(m_out));
    m_out = Array<u8>(m_alloc);
    return res;
}

Array<u8> DeflateStream::finish() {
    if (!m_finished) {
        flush_block(true);
        if (m_format == StreamFormat::Zlib) {
            m_out.push_back(as<u8>((m_adler >> 24u) & 0xFFu));
            m_out.push_back(as<u8>((m_adler >> 16u) & 0xFFu));
            m_out.push_back(as<u8>((m_adler >> 8u) & 0xFFu));
            m_out.push_back(as<u8>(m_adler & 0xFFu));
        } else if (m_format == StreamFormat::Gzip) {
            for (u32 s = 0u; s < 32u; s += 8u) m_out.push_back(as<u8>((m_crc >> s) & 0xFFu));
            const u32 isize = as<u32>(m_total_in & 0xFFFFFFFFull);
            for (u32 s = 0u; s < 32u; s += 8u) m_out.push_back(as<u8>((isize >> s) & 0xFFu));
        }
        m_finished = true;
    }
    return take_output();
}

// ---------------------------------------------------------------------------
// Streaming InflateStream (bounded 32 KiB sliding window)
// ---------------------------------------------------------------------------
ErrorCode InflateStream::StreamHuff::build(const u8* lens, i32 count, bool allow_empty) {
    for (usize i = 0u; i < kPrimarySize; ++i) primary[i] = kInvalid;
    sub.clear();
    empty = false;

    i32 bl_count[16] = {};
    i32 max_len = 0;
    for (i32 i = 0; i < count; ++i) {
        const i32 len = as<i32>(lens[i]);
        if (len > 15) return ErrorCode::InvalidData;
        if (len > 0) {
            ++bl_count[len];
            if (len > max_len) max_len = len;
        }
    }
    if (max_len == 0) {
        empty = true;
        return allow_empty ? ErrorCode::Ok : ErrorCode::InvalidData;
    }

    i32 left = 1;
    for (i32 bits = 1; bits <= max_len; ++bits) {
        left <<= 1;
        left -= bl_count[bits];
        if (left < 0) return ErrorCode::InvalidData;
    }

    u16 next_code[16] = {};
    u16 code = 0u;
    for (i32 bits = 1; bits <= max_len; ++bits) {
        code = as<u16>((code + as<u16>(bl_count[bits - 1])) << 1u);
        next_code[bits] = code;
    }

    u16 sym_codes[320] = {};
    u8 sub_max[kPrimarySize] = {};
    constexpr u64 kMask = kPrimarySize - 1u;
    for (i32 i = 0; i < count; ++i) {
        const i32 len = as<i32>(lens[i]);
        if (len == 0) continue;
        const u16 rev = bit_reverse(next_code[len]++, len);
        sym_codes[i] = rev;
        if (len > kPrimaryBits) {
            const usize p = as<usize>(rev & kMask);
            const u8 ex = as<u8>(len - kPrimaryBits);
            if (ex > sub_max[p]) sub_max[p] = ex;
        }
    }

    for (usize p = 0u; p < kPrimarySize; ++p) {
        if (sub_max[p] > 0u) {
            const usize off = sub.size();
            const usize sz = usize{1u} << as<u32>(sub_max[p]);
            for (usize k = 0u; k < sz; ++k) sub.push_back(kInvalid);
            primary[p] = (as<u32>(off) << 16u) | (as<u32>(sub_max[p]) << 8u) | 1u;
        }
    }

    for (i32 i = 0; i < count; ++i) {
        const i32 len = as<i32>(lens[i]);
        if (len == 0) continue;
        const u16 rev = sym_codes[i];
        if (len <= kPrimaryBits) {
            const u32 entry = (as<u32>(i) << 16u) | (as<u32>(len) << 8u);
            const usize step = usize{1u} << as<u32>(len);
            for (usize idx = as<usize>(rev); idx < kPrimarySize; idx += step) {
                if (primary[idx] != kInvalid) return ErrorCode::InvalidData;
                primary[idx] = entry;
            }
        } else {
            const usize p = as<usize>(rev & kMask);
            const u32 pe = primary[p];
            const usize off = as<usize>(pe >> 16u);
            const i32 sb = as<i32>((pe >> 8u) & 0xFFu);
            const usize ssz = usize{1u} << as<u32>(sb);
            const i32 ex = len - kPrimaryBits;
            const u32 entry = (as<u32>(i) << 16u) | (as<u32>(ex) << 8u);
            const usize step = usize{1u} << as<u32>(ex);
            for (usize idx = as<usize>(rev >> as<u32>(kPrimaryBits)); idx < ssz; idx += step) {
                if (sub[off + idx] != kInvalid) return ErrorCode::InvalidData;
                sub[off + idx] = entry;
            }
        }
    }
    return ErrorCode::Ok;
}

InflateStream::InflateStream(StreamFormat fmt, const InflateOptions& opts)
    : m_format(fmt),
      m_max_out(opts.max_output_bytes),
      m_alloc(opts.allocator ? opts.allocator : default_allocator()),
      m_window(32768u, u8{0u}, m_alloc),
      m_lit_tree(m_alloc),
      m_dist_tree(m_alloc),
      m_cl_tree(m_alloc) {
    if (fmt == StreamFormat::Zlib) {
        m_state = State::ZlibHdr;
        m_tmp_need = 2u;
    } else if (fmt == StreamFormat::Gzip) {
        m_state = State::GzipHdrFixed;
        m_tmp_need = 10u;
    } else {
        m_state = State::BlockHdr;
    }
}

void InflateStream::reset_for_next_gzip_member() noexcept {
    m_bit_buf = 0u;
    m_bit_count = 0;
    m_win_pos = 0u;
    m_win_fill = 0u;
    m_bfinal = false;
    m_finished = false;
    m_crc = 0u;
    m_member_out = 0u;
    m_tmp_pos = 0u;
    m_tmp_need = 10u;
    m_gz_flg = 0u;
    m_gz_hcrc = 0u;
    m_state = State::GzipHdrFixed;
}

ErrorCode InflateStream::emit_byte(u8 b, Array<u8>& out) {
    if (m_max_out > 0u && m_total_out >= m_max_out) [[unlikely]] {
        m_error = ErrorCode::OutOfRange;
        m_state = State::Failed;
        return m_error;
    }
    out.push_back(b);
    m_window[m_win_pos] = b;
    m_win_pos = (m_win_pos + 1u) & 32767u;
    if (m_win_fill < 32768u) ++m_win_fill;
    ++m_member_out;
    ++m_total_out;
    if (m_format == StreamFormat::Zlib) {
        m_adler = adler32_update(m_adler, ArrayRef<u8>(&b, 1u));
    } else if (m_format == StreamFormat::Gzip) {
        m_crc = crc32_update(m_crc, ArrayRef<u8>(&b, 1u));
    }
    return ErrorCode::Ok;
}

ErrorCode InflateStream::emit_match(usize length, usize dist, Array<u8>& out) {
    if (dist == 0u || dist > m_win_fill) [[unlikely]] {
        m_error = ErrorCode::InvalidData;
        m_state = State::Failed;
        return m_error;
    }
    if (m_max_out > 0u && (length > m_max_out || m_total_out > m_max_out - length)) [[unlikely]] {
        m_error = ErrorCode::OutOfRange;
        m_state = State::Failed;
        return m_error;
    }
    const usize old_sz = out.size();
    out.resize(old_sz + length);
    u8* dst = out.data() + old_sz;
    for (usize k = 0u; k < length; ++k) {
        const u8 b = m_window[(m_win_pos - dist) & 32767u];
        dst[k] = b;
        m_window[m_win_pos] = b;
        m_win_pos = (m_win_pos + 1u) & 32767u;
        if (m_win_fill < 32768u) ++m_win_fill;
    }
    m_member_out += length;
    m_total_out += length;
    if (m_format == StreamFormat::Zlib) {
        m_adler = adler32_update(m_adler, ArrayRef<u8>(dst, length));
    } else if (m_format == StreamFormat::Gzip) {
        m_crc = crc32_update(m_crc, ArrayRef<u8>(dst, length));
    }
    return ErrorCode::Ok;
}

ErrorCode InflateStream::push(ArrayRef<u8> chunk, Array<u8>& out) {
    if (m_error != ErrorCode::Ok) return m_error;

    const u8* data = chunk.data();
    const usize len = chunk.size();
    usize pos = 0u;

    auto fail = [&](ErrorCode ec) noexcept -> ErrorCode {
        m_error = ec;
        m_state = State::Failed;
        return ec;
    };

    auto refill = [&]() noexcept {
        while (m_bit_count <= 56 && pos < len) {
            m_bit_buf |= as<u64>(data[pos++]) << as<u32>(m_bit_count);
            m_bit_count += 8;
        }
    };

    auto take_bits = [&](i32 n, u32& val) noexcept -> bool {
        if (m_bit_count < n) refill();
        if (m_bit_count < n) return false;
        val = (n == 0) ? 0u : as<u32>(m_bit_buf & ((u64{1u} << as<u32>(n)) - 1u));
        m_bit_buf >>= as<u32>(n);
        m_bit_count -= n;
        return true;
    };

    auto align_byte_pull = [&](u8& byte_out) noexcept -> bool {
        const i32 disc = m_bit_count & 7;
        if (disc > 0) {
            m_bit_buf >>= as<u32>(disc);
            m_bit_count -= disc;
        }
        if (m_bit_count >= 8) {
            byte_out = as<u8>(m_bit_buf & 0xFFu);
            m_bit_buf >>= 8u;
            m_bit_count -= 8;
            return true;
        }
        if (pos < len) {
            byte_out = data[pos++];
            return true;
        }
        return false;
    };

    // Returns: 1 = decoded sym, 0 = need more input, -1 = invalid data
    auto decode_huff = [&](const StreamHuff& h, i32& sym_out) noexcept -> i32 {
        if (h.empty) return -1;
        if (m_bit_count < 15) refill();
        if (m_bit_count == 0) return 0;

        constexpr u64 kMask = StreamHuff::kPrimarySize - 1u;
        const u32 entry = h.primary[as<usize>(m_bit_buf & kMask)];
        const u32 kind = entry & 0xFFu;
        if (kind == 0u) [[likely]] {
            const i32 clen = as<i32>((entry >> 8u) & 0xFFu);
            if (clen > m_bit_count) return 0;
            m_bit_buf >>= as<u32>(clen);
            m_bit_count -= clen;
            sym_out = as<i32>(entry >> 16u);
            return 1;
        }
        if (kind == 1u) {
            if (m_bit_count <= StreamHuff::kPrimaryBits) return 0;
            const usize off = as<usize>(entry >> 16u);
            const i32 sb = as<i32>((entry >> 8u) & 0xFFu);
            const u64 smask = (u64{1u} << as<u32>(sb)) - 1u;
            const u64 sval = (m_bit_buf >> as<u32>(StreamHuff::kPrimaryBits)) & smask;
            const u32 se = h.sub[off + as<usize>(sval)];
            if ((se & 0xFFu) != 0u) {
                const i32 rem = m_bit_count - StreamHuff::kPrimaryBits;
                if (rem < sb) {
                    const u64 rmask = (u64{1u} << as<u32>(rem)) - 1u;
                    const usize ssz = usize{1u} << as<u32>(sb);
                    const usize step = usize{1u} << as<u32>(rem);
                    for (usize idx = as<usize>(sval & rmask); idx < ssz; idx += step) {
                        if ((h.sub[off + idx] & 0xFFu) == 0u) return 0;
                    }
                }
                return -1;
            }
            const i32 total = StreamHuff::kPrimaryBits + as<i32>((se >> 8u) & 0xFFu);
            if (total > m_bit_count) return 0;
            m_bit_buf >>= as<u32>(total);
            m_bit_count -= total;
            sym_out = as<i32>(se >> 16u);
            return 1;
        }
        if (m_bit_count < StreamHuff::kPrimaryBits) {
            const u64 mask = (u64{1u} << as<u32>(m_bit_count)) - 1u;
            const usize step = usize{1u} << as<u32>(m_bit_count);
            for (usize idx = as<usize>(m_bit_buf & mask); idx < StreamHuff::kPrimarySize; idx += step) {
                if (h.primary[idx] != StreamHuff::kInvalid) return 0;
            }
        }
        return -1;
    };

    while (true) {
        switch (m_state) {
        case State::ZlibHdr: {
            u8 b = 0u;
            while (m_tmp_pos < 2u && align_byte_pull(b)) m_tmp[m_tmp_pos++] = b;
            if (m_tmp_pos < 2u) return ErrorCode::Ok;
            const u8 cmf = m_tmp[0];
            const u8 flg = m_tmp[1];
            if (((as<u32>(cmf) << 8u) + as<u32>(flg)) % 31u != 0u) return fail(ErrorCode::InvalidData);
            if ((cmf & 0x0Fu) != 8u || (cmf >> 4u) > 7u) return fail(ErrorCode::NotSupported);
            if ((flg & 0x20u) != 0u) return fail(ErrorCode::NotSupported);
            m_state = State::BlockHdr;
            break;
        }

        case State::GzipHdrFixed: {
            u8 b = 0u;
            while (m_tmp_pos < 10u && align_byte_pull(b)) {
                m_tmp[m_tmp_pos++] = b;
                m_gz_hcrc = crc32_update(m_gz_hcrc, ArrayRef<u8>(&b, 1u));
            }
            if (m_tmp_pos < 10u) return ErrorCode::Ok;
            if (m_tmp[0] != 0x1Fu || m_tmp[1] != 0x8Bu) return fail(ErrorCode::InvalidData);
            if (m_tmp[2] != 8u) return fail(ErrorCode::NotSupported);
            m_gz_flg = m_tmp[3];
            if ((m_gz_flg & 0xE0u) != 0u) return fail(ErrorCode::InvalidData);
            m_tmp_pos = 0u;
            if ((m_gz_flg & 0x04u) != 0u) m_state = State::GzipExtraLen;
            else if ((m_gz_flg & 0x08u) != 0u) m_state = State::GzipNameSkip;
            else if ((m_gz_flg & 0x10u) != 0u) m_state = State::GzipCommentSkip;
            else if ((m_gz_flg & 0x02u) != 0u) m_state = State::GzipHcrc;
            else m_state = State::BlockHdr;
            break;
        }

        case State::GzipExtraLen: {
            u8 b = 0u;
            while (m_tmp_pos < 2u && align_byte_pull(b)) {
                m_tmp[m_tmp_pos++] = b;
                m_gz_hcrc = crc32_update(m_gz_hcrc, ArrayRef<u8>(&b, 1u));
            }
            if (m_tmp_pos < 2u) return ErrorCode::Ok;
            m_stored_rem = as<usize>(m_tmp[0]) | (as<usize>(m_tmp[1]) << 8u);
            m_tmp_pos = 0u;
            m_state = State::GzipExtraSkip;
            break;
        }

        case State::GzipExtraSkip: {
            u8 b = 0u;
            while (m_stored_rem > 0u && align_byte_pull(b)) {
                m_gz_hcrc = crc32_update(m_gz_hcrc, ArrayRef<u8>(&b, 1u));
                --m_stored_rem;
            }
            if (m_stored_rem > 0u) return ErrorCode::Ok;
            if ((m_gz_flg & 0x08u) != 0u) m_state = State::GzipNameSkip;
            else if ((m_gz_flg & 0x10u) != 0u) m_state = State::GzipCommentSkip;
            else if ((m_gz_flg & 0x02u) != 0u) m_state = State::GzipHcrc;
            else m_state = State::BlockHdr;
            break;
        }

        case State::GzipNameSkip: {
            u8 b = 0u;
            bool done = false;
            while (align_byte_pull(b)) {
                m_gz_hcrc = crc32_update(m_gz_hcrc, ArrayRef<u8>(&b, 1u));
                if (b == 0u) { done = true; break; }
            }
            if (!done) return ErrorCode::Ok;
            if ((m_gz_flg & 0x10u) != 0u) m_state = State::GzipCommentSkip;
            else if ((m_gz_flg & 0x02u) != 0u) m_state = State::GzipHcrc;
            else m_state = State::BlockHdr;
            break;
        }

        case State::GzipCommentSkip: {
            u8 b = 0u;
            bool done = false;
            while (align_byte_pull(b)) {
                m_gz_hcrc = crc32_update(m_gz_hcrc, ArrayRef<u8>(&b, 1u));
                if (b == 0u) { done = true; break; }
            }
            if (!done) return ErrorCode::Ok;
            m_state = ((m_gz_flg & 0x02u) != 0u) ? State::GzipHcrc : State::BlockHdr;
            break;
        }

        case State::GzipHcrc: {
            u8 b = 0u;
            while (m_tmp_pos < 2u && align_byte_pull(b)) m_tmp[m_tmp_pos++] = b;
            if (m_tmp_pos < 2u) return ErrorCode::Ok;
            const u16 exp = as<u16>(as<u16>(m_tmp[0]) | (as<u16>(m_tmp[1]) << 8u));
            if (exp != as<u16>(m_gz_hcrc & 0xFFFFu)) return fail(ErrorCode::InvalidData);
            m_tmp_pos = 0u;
            m_state = State::BlockHdr;
            break;
        }

        case State::BlockHdr: {
            u32 hdr = 0u;
            if (!take_bits(3, hdr)) return ErrorCode::Ok;
            m_bfinal = (hdr & 1u) != 0u;
            const u32 btype = hdr >> 1u;
            if (btype == 0u) {
                m_tmp_pos = 0u;
                m_state = State::StoredHdr;
            } else if (btype == 1u) {
                u8 lit_lens[288];
                for (i32 i = 0; i <= 143; ++i) lit_lens[i] = 8u;
                for (i32 i = 144; i <= 255; ++i) lit_lens[i] = 9u;
                for (i32 i = 256; i <= 279; ++i) lit_lens[i] = 7u;
                for (i32 i = 280; i <= 287; ++i) lit_lens[i] = 8u;
                u8 dist_lens[32];
                for (i32 i = 0; i < 32; ++i) dist_lens[i] = 5u;
                [[maybe_unused]] const ErrorCode e1 = m_lit_tree.build(lit_lens, 288);
                [[maybe_unused]] const ErrorCode e2 = m_dist_tree.build(dist_lens, 32);
                m_state = State::DecodeLitLen;
            } else if (btype == 2u) {
                m_state = State::DynHdr;
            } else {
                return fail(ErrorCode::InvalidData);
            }
            break;
        }

        case State::StoredHdr: {
            u8 b = 0u;
            while (m_tmp_pos < 4u && align_byte_pull(b)) m_tmp[m_tmp_pos++] = b;
            if (m_tmp_pos < 4u) return ErrorCode::Ok;
            const u16 blen = as<u16>(as<u16>(m_tmp[0]) | (as<u16>(m_tmp[1]) << 8u));
            const u16 nlen = as<u16>(as<u16>(m_tmp[2]) | (as<u16>(m_tmp[3]) << 8u));
            if (as<u16>(blen ^ 0xFFFFu) != nlen) return fail(ErrorCode::InvalidData);
            m_stored_rem = as<usize>(blen);
            m_tmp_pos = 0u;
            m_state = State::StoredBody;
            break;
        }

        case State::StoredBody: {
            u8 b = 0u;
            while (m_stored_rem > 0u && align_byte_pull(b)) {
                const ErrorCode ec = emit_byte(b, out);
                if (ec != ErrorCode::Ok) return ec;
                --m_stored_rem;
            }
            if (m_stored_rem > 0u) return ErrorCode::Ok;
            if (m_bfinal) {
                m_tmp_pos = 0u;
                if (m_format == StreamFormat::Zlib) m_state = State::ZlibTrailer;
                else if (m_format == StreamFormat::Gzip) m_state = State::GzipTrailer;
                else { m_finished = true; m_state = State::Done; }
            } else {
                m_state = State::BlockHdr;
            }
            break;
        }

        case State::DynHdr: {
            u32 bits = 0u;
            if (!take_bits(14, bits)) return ErrorCode::Ok;
            m_hlit = as<i32>(bits & 0x1Fu) + 257;
            m_hdist = as<i32>((bits >> 5u) & 0x1Fu) + 1;
            m_hclen = as<i32>((bits >> 10u) & 0x0Fu) + 4;
            if (m_hlit > 286 || m_hdist > 30) return fail(ErrorCode::InvalidData);
            for (i32 i = 0; i < 19; ++i) m_cl_lens[i] = 0u;
            m_cl_idx = 0;
            m_state = State::DynClLens;
            break;
        }

        case State::DynClLens: {
            while (m_cl_idx < m_hclen) {
                u32 v = 0u;
                if (!take_bits(3, v)) return ErrorCode::Ok;
                m_cl_lens[kCodeLengthOrder[m_cl_idx++]] = as<u8>(v);
            }
            const ErrorCode ec = m_cl_tree.build(m_cl_lens, 19);
            if (ec != ErrorCode::Ok) return fail(ec);
            for (i32 i = 0; i < 320; ++i) m_all_lens[i] = 0u;
            m_lens_idx = 0;
            m_pending_cl_sym = -1;
            m_state = State::DynCodeLens;
            break;
        }

        case State::DynCodeLens: {
            const i32 total = m_hlit + m_hdist;
            while (m_lens_idx < total) {
                if (m_pending_cl_sym < 0) {
                    i32 sym = 0;
                    const i32 rc = decode_huff(m_cl_tree, sym);
                    if (rc == 0) return ErrorCode::Ok;
                    if (rc < 0) return fail(ErrorCode::InvalidData);
                    if (sym < 16) {
                        m_all_lens[m_lens_idx++] = as<u8>(sym);
                        continue;
                    }
                    m_pending_cl_sym = sym;
                }
                const i32 sym = m_pending_cl_sym;
                if (sym == 16) {
                    if (m_lens_idx == 0) return fail(ErrorCode::InvalidData);
                    u32 ex = 0u;
                    if (!take_bits(2, ex)) return ErrorCode::Ok;
                    const i32 rep = as<i32>(ex) + 3;
                    if (m_lens_idx + rep > total) return fail(ErrorCode::InvalidData);
                    const u8 prev = m_all_lens[m_lens_idx - 1];
                    for (i32 r = 0; r < rep; ++r) m_all_lens[m_lens_idx++] = prev;
                } else if (sym == 17 || sym == 18) {
                    const i32 ebits = (sym == 17) ? 3 : 7;
                    const i32 base = (sym == 17) ? 3 : 11;
                    u32 ex = 0u;
                    if (!take_bits(ebits, ex)) return ErrorCode::Ok;
                    const i32 rep = as<i32>(ex) + base;
                    if (m_lens_idx + rep > total) return fail(ErrorCode::InvalidData);
                    for (i32 r = 0; r < rep; ++r) m_all_lens[m_lens_idx++] = 0u;
                } else {
                    return fail(ErrorCode::InvalidData);
                }
                m_pending_cl_sym = -1;
            }
            if (m_all_lens[256] == 0u) return fail(ErrorCode::InvalidData);
            ErrorCode ec = m_lit_tree.build(m_all_lens, m_hlit);
            if (ec != ErrorCode::Ok) return fail(ec);
            ec = m_dist_tree.build(m_all_lens + m_hlit, m_hdist, true);
            if (ec != ErrorCode::Ok) return fail(ec);
            m_state = State::DecodeLitLen;
            break;
        }

        case State::DecodeLitLen: {
            i32 sym = 0;
            const i32 rc = decode_huff(m_lit_tree, sym);
            if (rc == 0) return ErrorCode::Ok;
            if (rc < 0) return fail(ErrorCode::InvalidData);
            if (sym < 256) [[likely]] {
                const ErrorCode ec = emit_byte(as<u8>(sym), out);
                if (ec != ErrorCode::Ok) return ec;
            } else if (sym == 256) {
                if (m_bfinal) {
                    m_tmp_pos = 0u;
                    if (m_format == StreamFormat::Zlib) m_state = State::ZlibTrailer;
                    else if (m_format == StreamFormat::Gzip) m_state = State::GzipTrailer;
                    else { m_finished = true; m_state = State::Done; }
                } else {
                    m_state = State::BlockHdr;
                }
            } else if (sym <= 285) {
                m_pending_len_idx = sym - 257;
                m_state = State::DecodeLenExtra;
            } else {
                return fail(ErrorCode::InvalidData);
            }
            break;
        }

        case State::DecodeLenExtra: {
            const i32 ebits = kExtraLengthBits[m_pending_len_idx];
            u32 ex = 0u;
            if (ebits > 0 && !take_bits(ebits, ex)) return ErrorCode::Ok;
            m_pending_length = as<usize>(kLengthBase[m_pending_len_idx]) + as<usize>(ex);
            m_state = State::DecodeDist;
            break;
        }

        case State::DecodeDist: {
            i32 dsym = 0;
            const i32 rc = decode_huff(m_dist_tree, dsym);
            if (rc == 0) return ErrorCode::Ok;
            if (rc < 0 || dsym < 0 || dsym >= 30) return fail(ErrorCode::InvalidData);
            m_pending_dist_sym = dsym;
            m_state = State::DecodeDistExtra;
            break;
        }

        case State::DecodeDistExtra: {
            const i32 ebits = kExtraDistBits[m_pending_dist_sym];
            u32 ex = 0u;
            if (ebits > 0 && !take_bits(ebits, ex)) return ErrorCode::Ok;
            const usize dist = as<usize>(kDistBase[m_pending_dist_sym]) + as<usize>(ex);
            const ErrorCode ec = emit_match(m_pending_length, dist, out);
            if (ec != ErrorCode::Ok) return ec;
            m_state = State::DecodeLitLen;
            break;
        }

        case State::ZlibTrailer: {
            u8 b = 0u;
            while (m_tmp_pos < 4u && align_byte_pull(b)) m_tmp[m_tmp_pos++] = b;
            if (m_tmp_pos < 4u) return ErrorCode::Ok;
            const u32 exp_adler = (as<u32>(m_tmp[0]) << 24u) | (as<u32>(m_tmp[1]) << 16u) |
                                  (as<u32>(m_tmp[2]) << 8u) | as<u32>(m_tmp[3]);
            if (exp_adler != m_adler) return fail(ErrorCode::InvalidData);
            m_finished = true;
            m_state = State::Done;
            break;
        }

        case State::GzipTrailer: {
            u8 b = 0u;
            while (m_tmp_pos < 8u && align_byte_pull(b)) m_tmp[m_tmp_pos++] = b;
            if (m_tmp_pos < 8u) return ErrorCode::Ok;
            const u32 exp_crc = as<u32>(m_tmp[0]) | (as<u32>(m_tmp[1]) << 8u) |
                                (as<u32>(m_tmp[2]) << 16u) | (as<u32>(m_tmp[3]) << 24u);
            const u32 exp_isize = as<u32>(m_tmp[4]) | (as<u32>(m_tmp[5]) << 8u) |
                                  (as<u32>(m_tmp[6]) << 16u) | (as<u32>(m_tmp[7]) << 24u);
            if (exp_crc != m_crc || exp_isize != as<u32>(as<u64>(m_member_out) & 0xFFFFFFFFull)) {
                return fail(ErrorCode::InvalidData);
            }
            m_finished = true;
            m_state = State::GzipNextMember;
            break;
        }

        case State::GzipNextMember: {
            u8 b = 0u;
            if (!align_byte_pull(b)) return ErrorCode::Ok;
            // Start of next concatenated GZIP member
            reset_for_next_gzip_member();
            m_tmp[0] = b;
            m_tmp_pos = 1u;
            m_gz_hcrc = crc32_update(0u, ArrayRef<u8>(&b, 1u));
            break;
        }

        case State::Done:
            return ErrorCode::Ok;

        case State::Failed:
            return m_error;
        }
    }
}

ErrorCode InflateStream::finish() noexcept {
    if (m_error != ErrorCode::Ok) return m_error;
    if (!m_finished) {
        m_error = ErrorCode::EndOfFile;
        m_state = State::Failed;
        return m_error;
    }
    return ErrorCode::Ok;
}

} // namespace keel::compress
