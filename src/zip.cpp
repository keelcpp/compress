#include "keel/compress/zip.h"

#include "keel/compress/checksum.h"
#include "keel/memory.h"

namespace keel::compress {

namespace {

constexpr u32 kSigLocalFile = 0x04034B50u;
constexpr u32 kSigCentralDir = 0x02014B50u;
constexpr u32 kSigEocd = 0x06054B50u;
constexpr u32 kSigZip64Eocd = 0x06064B50u;
constexpr u32 kSigZip64Locator = 0x07064B50u;

constexpr u16 kFlagEncrypted = 1u << 0u;
constexpr u16 kFlagUtf8 = 1u << 11u;

constexpr u16 load_le16(const u8* p) noexcept {
    return as<u16>(as<u16>(p[0]) | (as<u16>(p[1]) << 8u));
}

constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) | (as<u32>(p[3]) << 24u);
}

constexpr u64 load_le64(const u8* p) noexcept {
    return as<u64>(load_le32(p)) | (as<u64>(load_le32(p + 4u)) << 32u);
}

void push_le16(Array<u8>& out, u16 v) {
    out.push_back(as<u8>(v & 0xFFu));
    out.push_back(as<u8>((v >> 8u) & 0xFFu));
}

void push_le32(Array<u8>& out, u32 v) {
    out.push_back(as<u8>(v & 0xFFu));
    out.push_back(as<u8>((v >> 8u) & 0xFFu));
    out.push_back(as<u8>((v >> 16u) & 0xFFu));
    out.push_back(as<u8>((v >> 24u) & 0xFFu));
}

bool has_non_ascii(StringRef s) noexcept {
    for (usize i = 0u; i < s.size(); ++i) {
        if ((as<u8>(s.data()[i]) & 0x80u) != 0u) return true;
    }
    return false;
}

} // namespace

bool is_safe_zip_path(StringRef path) noexcept {
    if (path.empty()) return false;
    if (path.data()[0] == '/' || path.data()[0] == '\\') return false;
    if (path.size() >= 2u && path.data()[1] == ':') return false;

    usize seg_start = 0u;
    for (usize i = 0u; i <= path.size(); ++i) {
        const bool is_end = (i == path.size());
        const char c = is_end ? '/' : path.data()[i];
        if (!is_end && c == '\0') return false;
        if (c == '/' || c == '\\') {
            const usize seg_len = i - seg_start;
            if (seg_len == 2u && path.data()[seg_start] == '.' && path.data()[seg_start + 1u] == '.') {
                return false;
            }
            seg_start = i + 1u;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// ZipReader
// ---------------------------------------------------------------------------
Result<ZipReader> ZipReader::open(ArrayRef<u8> archive, Allocator* alloc) {
    constexpr usize kMinEocdSize = 22u;
    if (archive.size() < kMinEocdSize) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }

    // Locate EOCD scanning backwards within the trailing 64 KiB + 22 bytes
    const usize max_back = keel::min<usize>(archive.size(), 65535u + kMinEocdSize);
    const usize search_start = archive.size() - max_back;
    usize eocd_pos = kInvalidIndex;
    for (usize pos = archive.size() - kMinEocdSize;; --pos) {
        if (load_le32(archive.data() + pos) == kSigEocd) {
            const usize comment_len = as<usize>(load_le16(archive.data() + pos + 20u));
            if (pos + kMinEocdSize + comment_len == archive.size()) {
                eocd_pos = pos;
                break;
            }
        }
        if (pos == search_start) break;
    }

    if (eocd_pos == kInvalidIndex) [[unlikely]] {
        return ErrorCode::InvalidData;
    }

    const u8* eocd = archive.data() + eocd_pos;
    u32 disk_num = load_le16(eocd + 4u);
    u32 cd_disk = load_le16(eocd + 6u);
    u64 disk_entries = load_le16(eocd + 8u);
    u64 total_entries = load_le16(eocd + 10u);
    u64 cd_size = load_le32(eocd + 12u);
    u64 cd_offset = load_le32(eocd + 16u);
    const u16 comment_len = load_le16(eocd + 20u);

    const bool needs_zip64 = (disk_num == 0xFFFFu || cd_disk == 0xFFFFu ||
                              disk_entries == 0xFFFFu || total_entries == 0xFFFFu ||
                              cd_size == 0xFFFFFFFFu || cd_offset == 0xFFFFFFFFu);
    if (needs_zip64) {
        if (eocd_pos < 20u) [[unlikely]] return ErrorCode::InvalidData;
        const u8* loc = archive.data() + (eocd_pos - 20u);
        if (load_le32(loc) != kSigZip64Locator) [[unlikely]] return ErrorCode::InvalidData;
        const u32 loc_disk = load_le32(loc + 4u);
        const u64 z64_off = load_le64(loc + 8u);
        const u32 total_disks = load_le32(loc + 16u);
        if (loc_disk != 0u || total_disks > 1u) [[unlikely]] return ErrorCode::NotSupported;
        if (z64_off > as<u64>(eocd_pos - 20u) || as<u64>(eocd_pos - 20u) - z64_off < 56ull) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        const u8* z64 = archive.data() + as<usize>(z64_off);
        if (load_le32(z64) != kSigZip64Eocd) [[unlikely]] return ErrorCode::InvalidData;
        disk_num = load_le32(z64 + 16u);
        cd_disk = load_le32(z64 + 20u);
        disk_entries = load_le64(z64 + 24u);
        total_entries = load_le64(z64 + 32u);
        cd_size = load_le64(z64 + 40u);
        cd_offset = load_le64(z64 + 48u);
    }

    if (disk_num != 0u || cd_disk != 0u || disk_entries != total_entries) [[unlikely]] {
        return ErrorCode::NotSupported;
    }
    if (cd_offset > as<u64>(eocd_pos) || cd_size > as<u64>(eocd_pos) - cd_offset) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    // Sanity cap: each central directory entry is at least 46 bytes
    if (total_entries > cd_size / 46ull) [[unlikely]] {
        return ErrorCode::InvalidData;
    }

    Allocator* a = alloc ? alloc : default_allocator();
    ZipReader reader;
    reader.m_alloc = a;
    reader.m_archive = archive;
    reader.m_entries = Array<ZipEntry>(a);
    reader.m_entries.reserve(as<usize>(total_entries));
    if (comment_len > 0u) {
        reader.m_comment = String::from(
            StringRef(reinterpret_cast<const char*>(eocd + kMinEocdSize), as<usize>(comment_len)), a);
    } else {
        reader.m_comment = String(a);
    }

    usize pos = as<usize>(cd_offset);
    const usize cd_end = as<usize>(cd_offset) + as<usize>(cd_size);
    for (u64 idx = 0u; idx < total_entries; ++idx) {
        if (cd_end - pos < 46u) [[unlikely]] return ErrorCode::InvalidData;
        const u8* hdr = archive.data() + pos;
        if (load_le32(hdr) != kSigCentralDir) [[unlikely]] return ErrorCode::InvalidData;

        const u16 flags = load_le16(hdr + 8u);
        const u16 method = load_le16(hdr + 10u);
        const u32 crc = load_le32(hdr + 16u);
        u64 comp_sz = load_le32(hdr + 20u);
        u64 uncomp_sz = load_le32(hdr + 24u);
        const u16 name_len = load_le16(hdr + 28u);
        const u16 extra_len = load_le16(hdr + 30u);
        const u16 cmt_len = load_le16(hdr + 32u);
        u64 local_off = load_le32(hdr + 42u);

        const usize rec_len = 46u + as<usize>(name_len) + as<usize>(extra_len) + as<usize>(cmt_len);
        if (cd_end - pos < rec_len) [[unlikely]] return ErrorCode::InvalidData;

        // Parse ZIP64 Extended Information Extra Field (Header ID 0x0001) when sentinel values appear
        if (uncomp_sz == 0xFFFFFFFFu || comp_sz == 0xFFFFFFFFu || local_off == 0xFFFFFFFFu) {
            const u8* extra = hdr + 46u + as<usize>(name_len);
            usize epos = 0u;
            const usize eend = as<usize>(extra_len);
            while (eend - epos >= 4u) {
                const u16 eid = load_le16(extra + epos);
                const usize esz = as<usize>(load_le16(extra + epos + 2u));
                epos += 4u;
                if (eend - epos < esz) [[unlikely]] return ErrorCode::InvalidData;
                if (eid == 0x0001u) {
                    usize fpos = epos;
                    const usize fend = epos + esz;
                    if (uncomp_sz == 0xFFFFFFFFu) {
                        if (fend - fpos < 8u) return ErrorCode::InvalidData;
                        uncomp_sz = load_le64(extra + fpos);
                        fpos += 8u;
                    }
                    if (comp_sz == 0xFFFFFFFFu) {
                        if (fend - fpos < 8u) return ErrorCode::InvalidData;
                        comp_sz = load_le64(extra + fpos);
                        fpos += 8u;
                    }
                    if (local_off == 0xFFFFFFFFu) {
                        if (fend - fpos < 8u) return ErrorCode::InvalidData;
                        local_off = load_le64(extra + fpos);
                        fpos += 8u;
                    }
                    break;
                }
                epos += esz;
            }
        }

        ZipEntry entry{};
        entry.name = String::from(
            StringRef(reinterpret_cast<const char*>(hdr + 46u), as<usize>(name_len)), a);
        entry.method = method;
        entry.flags = flags;
        entry.crc32 = crc;
        entry.compressed_size = comp_sz;
        entry.uncompressed_size = uncomp_sz;
        entry.local_header_offset = local_off;

        reader.m_entries.push_back(keel::move(entry));
        pos += rec_len;
    }

    return reader;
}

Optional<usize> ZipReader::find(StringRef name) const noexcept {
    for (usize i = 0u; i < m_entries.size(); ++i) {
        if (m_entries[i].name.as_ref() == name) {
            return i;
        }
    }
    return Optional<usize>{};
}

Result<Array<u8>> ZipReader::extract(usize index, const InflateOptions& opts) const {
    if (index >= m_entries.size()) [[unlikely]] {
        return ErrorCode::OutOfRange;
    }
    const ZipEntry& e = m_entries[index];
    if ((e.flags & kFlagEncrypted) != 0u) [[unlikely]] {
        return ErrorCode::NotSupported;
    }
    if (opts.max_output_bytes > 0u && e.uncompressed_size > as<u64>(opts.max_output_bytes)) [[unlikely]] {
        return ErrorCode::OutOfRange;
    }

    if (e.local_header_offset > as<u64>(m_archive.size())) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    const usize loff = as<usize>(e.local_header_offset);
    if (m_archive.size() - loff < 30u) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    const u8* lhdr = m_archive.data() + loff;
    if (load_le32(lhdr) != kSigLocalFile) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    const u16 l_name_len = load_le16(lhdr + 26u);
    const u16 l_extra_len = load_le16(lhdr + 28u);
    const usize l_hdr_size = 30u + as<usize>(l_name_len) + as<usize>(l_extra_len);
    if (m_archive.size() - loff < l_hdr_size) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }
    const usize data_off = loff + l_hdr_size;
    if (e.compressed_size > as<u64>(m_archive.size() - data_off)) [[unlikely]] {
        return ErrorCode::EndOfFile;
    }

    const ArrayRef<u8> payload = m_archive.slice(data_off, as<usize>(e.compressed_size));
    Allocator* dst_alloc = opts.allocator ? opts.allocator : m_alloc;

    Array<u8> out(dst_alloc);
    if (e.method == as<u16>(ZipMethod::Store)) {
        if (e.compressed_size != e.uncompressed_size) [[unlikely]] {
            return ErrorCode::InvalidData;
        }
        out.reserve(payload.size());
        out.append(payload);
    } else if (e.method == as<u16>(ZipMethod::Deflate)) {
        InflateOptions io = opts;
        io.allocator = dst_alloc;
        if (io.expected_size_hint == 0u) io.expected_size_hint = as<usize>(e.uncompressed_size);
        KEEL_TRY_ASSIGN(out, inflate_raw(payload, io));
    } else {
        return ErrorCode::NotSupported;
    }

    if (out.size() != as<usize>(e.uncompressed_size)) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    if (crc32(out.as_ref()) != e.crc32) [[unlikely]] {
        return ErrorCode::InvalidData;
    }
    return out;
}

Result<Array<u8>> ZipReader::extract(StringRef name, const InflateOptions& opts) const {
    auto idx = find(name);
    if (!idx.has_value()) [[unlikely]] {
        return ErrorCode::NotFound;
    }
    return extract(*idx, opts);
}

// ---------------------------------------------------------------------------
// ZipWriter
// ---------------------------------------------------------------------------
ZipWriter::ZipWriter(Allocator* alloc)
    : m_alloc(alloc ? alloc : default_allocator()),
      m_buf(m_alloc),
      m_entries(m_alloc) {}

ErrorCode ZipWriter::add_file(StringRef name, ArrayRef<u8> data, i32 level) {
    if (m_finished) return ErrorCode::InvalidArgument;
    if (name.empty() || name.size() > 65535u) return ErrorCode::InvalidArgument;
    if (m_entries.size() >= 65534u) return ErrorCode::OutOfRange;
    if (as<u64>(data.size()) > 0xFFFFFFFFull || as<u64>(m_buf.size()) > 0xFFFFFFFFull) {
        return ErrorCode::OutOfRange;
    }

    const u32 crc = crc32(data);
    u16 method = as<u16>(ZipMethod::Store);
    Array<u8> deflated(m_alloc);
    ArrayRef<u8> payload = data;

    if (level > 0 && !data.empty()) {
        deflated = deflate_raw(data, level, m_alloc);
        if (deflated.size() < data.size()) {
            method = as<u16>(ZipMethod::Deflate);
            payload = deflated.as_ref();
        }
    }

    if (as<u64>(m_buf.size()) + 30ull + as<u64>(name.size()) + as<u64>(payload.size()) > 0xFFFFFFFFull) {
        return ErrorCode::OutOfRange;
    }

    const u16 flags = has_non_ascii(name) ? kFlagUtf8 : 0u;
    const u32 local_off = as<u32>(m_buf.size());

    // Local File Header (30 bytes + name)
    push_le32(m_buf, kSigLocalFile);
    push_le16(m_buf, 20u); // version needed: 2.0
    push_le16(m_buf, flags);
    push_le16(m_buf, method);
    push_le16(m_buf, 0u);  // mod time
    push_le16(m_buf, 0u);  // mod date
    push_le32(m_buf, crc);
    push_le32(m_buf, as<u32>(payload.size()));
    push_le32(m_buf, as<u32>(data.size()));
    push_le16(m_buf, as<u16>(name.size()));
    push_le16(m_buf, 0u);  // extra length
    m_buf.append(ArrayRef<u8>(reinterpret_cast<const u8*>(name.data()), name.size()));
    if (!payload.empty()) {
        m_buf.append(payload);
    }

    ZipEntry entry{};
    entry.name = String::from(name, m_alloc);
    entry.method = method;
    entry.flags = flags;
    entry.crc32 = crc;
    entry.compressed_size = as<u32>(payload.size());
    entry.uncompressed_size = as<u32>(data.size());
    entry.local_header_offset = local_off;
    m_entries.push_back(keel::move(entry));
    return ErrorCode::Ok;
}

ErrorCode ZipWriter::add_directory(StringRef name) {
    if (name.empty()) return ErrorCode::InvalidArgument;
    if (name.data()[name.size() - 1u] == '/') {
        return add_file(name, ArrayRef<u8>{}, 0);
    }
    String dir(m_alloc);
    dir.reserve(name.size() + 1u);
    dir.append(name);
    dir.push_back('/');
    return add_file(dir.as_ref(), ArrayRef<u8>{}, 0);
}

Array<u8> ZipWriter::finish(StringRef comment) {
    if (m_finished) return Array<u8>(m_alloc);
    m_finished = true;

    const u32 cd_offset = as<u32>(m_buf.size());
    for (usize i = 0u; i < m_entries.size(); ++i) {
        const ZipEntry& e = m_entries[i];
        push_le32(m_buf, kSigCentralDir);
        push_le16(m_buf, 20u); // version made by
        push_le16(m_buf, 20u); // version needed
        push_le16(m_buf, e.flags);
        push_le16(m_buf, e.method);
        push_le16(m_buf, 0u);  // mod time
        push_le16(m_buf, 0u);  // mod date
        push_le32(m_buf, e.crc32);
        push_le32(m_buf, as<u32>(e.compressed_size));
        push_le32(m_buf, as<u32>(e.uncompressed_size));
        push_le16(m_buf, as<u16>(e.name.size()));
        push_le16(m_buf, 0u);  // extra len
        push_le16(m_buf, 0u);  // comment len
        push_le16(m_buf, 0u);  // disk start
        push_le16(m_buf, 0u);  // internal attrs
        push_le32(m_buf, e.is_directory() ? 0x10u : 0u); // external attrs (DOS dir bit)
        push_le32(m_buf, as<u32>(e.local_header_offset));
        m_buf.append(ArrayRef<u8>(reinterpret_cast<const u8*>(e.name.data()), e.name.size()));
    }
    const u32 cd_size = as<u32>(m_buf.size()) - cd_offset;

    const usize cmt_len = keel::min<usize>(comment.size(), 65535u);
    push_le32(m_buf, kSigEocd);
    push_le16(m_buf, 0u);
    push_le16(m_buf, 0u);
    push_le16(m_buf, as<u16>(m_entries.size()));
    push_le16(m_buf, as<u16>(m_entries.size()));
    push_le32(m_buf, cd_size);
    push_le32(m_buf, cd_offset);
    push_le16(m_buf, as<u16>(cmt_len));
    if (cmt_len > 0u) {
        m_buf.append(ArrayRef<u8>(reinterpret_cast<const u8*>(comment.data()), cmt_len));
    }

    Array<u8> out(keel::move(m_buf));
    m_buf = Array<u8>(m_alloc);
    return out;
}

} // namespace keel::compress
