#pragma once

#include "keel/array.h"
#include "keel/compress/deflate.h"
#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"
#include "keel/result.h"
#include "keel/string.h"

namespace keel::compress {

enum class ZipMethod : u16 {
    Store = 0u,
    Deflate = 8u,
};

struct ZipEntry {
    String name;
    u16 method = 0u;
    u16 flags = 0u;
    u32 crc32 = 0u;
    u32 compressed_size = 0u;
    u32 uncompressed_size = 0u;
    u32 local_header_offset = 0u;

    [[nodiscard]] bool is_directory() const noexcept {
        return !name.empty() && name[name.size() - 1u] == '/';
    }
    [[nodiscard]] bool is_utf8() const noexcept {
        return (flags & 0x0800u) != 0u;
    }
};

// Returns true if `path` is a safe relative ZIP entry path (no leading '/', '\\',
// Windows drive letter, NUL byte, or '..' path component — prevents Zip Slip).
[[nodiscard]] bool is_safe_zip_path(StringRef path) noexcept;

// ---------------------------------------------------------------------------
// In-memory ZIP archive reader (PKWARE APPNOTE, Store & Deflate)
// ---------------------------------------------------------------------------
class ZipReader {
public:
    ZipReader() noexcept = default;
    ~ZipReader() noexcept = default;
    ZipReader(const ZipReader&) = delete;
    ZipReader& operator=(const ZipReader&) = delete;
    ZipReader(ZipReader&&) noexcept = default;
    ZipReader& operator=(ZipReader&&) noexcept = default;

    // Parses the Central Directory of `archive`. `archive` must stay alive while calling extract().
    [[nodiscard]] static Result<ZipReader> open(ArrayRef<u8> archive, Allocator* alloc = nullptr);

    [[nodiscard]] usize entry_count() const noexcept { return m_entries.size(); }
    [[nodiscard]] const ZipEntry& entry(usize index) const noexcept { return m_entries[index]; }
    [[nodiscard]] StringRef comment() const noexcept { return m_comment.as_ref(); }

    [[nodiscard]] Optional<usize> find(StringRef name) const noexcept;

    [[nodiscard]] Result<Array<u8>> extract(usize index, const InflateOptions& opts = {}) const;
    [[nodiscard]] Result<Array<u8>> extract(StringRef name, const InflateOptions& opts = {}) const;

private:
    ArrayRef<u8> m_archive{};
    Array<ZipEntry> m_entries;
    String m_comment;
    Allocator* m_alloc = nullptr;
};

// ---------------------------------------------------------------------------
// In-memory ZIP archive writer (PKWARE APPNOTE, Store & Deflate)
// ---------------------------------------------------------------------------
class ZipWriter {
public:
    explicit ZipWriter(Allocator* alloc = nullptr);
    ~ZipWriter() noexcept = default;
    ZipWriter(const ZipWriter&) = delete;
    ZipWriter& operator=(const ZipWriter&) = delete;
    ZipWriter(ZipWriter&&) noexcept = default;
    ZipWriter& operator=(ZipWriter&&) noexcept = default;

    // Adds a file entry. level <= 0 stores uncompressed; level 1..9 uses Deflate
    // (automatically falling back to Store if Deflate does not shrink the payload).
    [[nodiscard]] ErrorCode add_file(StringRef name, ArrayRef<u8> data, i32 level = 6);

    // Adds a directory entry (appends trailing '/' if not already present).
    [[nodiscard]] ErrorCode add_directory(StringRef name);

    // Writes the Central Directory and EOCD record, returning the complete .zip archive.
    [[nodiscard]] Array<u8> finish(StringRef comment = {});

    [[nodiscard]] usize entry_count() const noexcept { return m_entries.size(); }

private:
    Allocator* m_alloc = nullptr;
    Array<u8> m_buf;
    Array<ZipEntry> m_entries;
    bool m_finished = false;
};

} // namespace keel::compress
