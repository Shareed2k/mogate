#ifndef MG_SIP_DARWIN_H
#define MG_SIP_DARWIN_H

// SIP detection + injectable-slice selection for the injector dylib. This is a
// C port of pkg/local/sip_darwin.go (needsSIPPatch / chooseSlice); the two must
// agree byte-for-byte on which slice is chosen (Task E1 enforces this with
// golden vectors). Everything here is guarded by __APPLE__: the injector also
// builds on linux, which has no System Integrity Protection.
//
// The whole file is included by BOTH injector/main.go's cgo comment block (so
// the built dylib carries these functions) and the darwin cgo test bridge (so
// the test can exercise them). Those are two separate translation units, so all
// functions are `static`: each TU gets its own copy and there is no
// duplicate-symbol link error.

#ifdef __APPLE__

#include <crt_externs.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Constants mirror pkg/local/sip_darwin.go exactly. They are re-declared here
// rather than taken from the SDK headers so the C and Go ports are provably the
// same values.

// SF_RESTRICTED: the file flag (stat.st_flags) that marks a SIP-protected file.
#define MG_SIP_SF_RESTRICTED 0x00080000u

// cpu type/subtype (mach/machine.h) used to pick a loadable slice.
#define MG_SIP_CPU_TYPE_X86_64 0x01000007u
#define MG_SIP_CPU_TYPE_ARM64 0x0100000cu
#define MG_SIP_CPU_SUBTYPE_ARM64E 2u

// Mach-O / fat magics (read big-endian for fat, host order for thin).
#define MG_SIP_FAT_MAGIC 0xcafebabeu
#define MG_SIP_FAT_MAGIC_64 0xcafebabfu
#define MG_SIP_MH_MAGIC 0xfeedfaceu
#define MG_SIP_MH_MAGIC_64 0xfeedfacfu

// Code-signing constants (cs_blobs.h). All CS fields are big-endian.
#define MG_SIP_CS_MAGIC_EMBEDDED 0xfade0cc0u
#define MG_SIP_CS_MAGIC_CODEDIR 0xfade0c02u
#define MG_SIP_CS_SLOT_CODEDIR 0u
#define MG_SIP_CS_SLOT_ENTITLEMENTS 5u
#define MG_SIP_CS_RESTRICT 0x0000800u
#define MG_SIP_CS_RUNTIME 0x00010000u
#define MG_SIP_CS_BLOB_INDEX_SIZE 8u
#define MG_SIP_CS_MAX_BLOB_COUNT (1u << 16)

// LC_CODE_SIGNATURE load command; its body is a linkedit_data_command
// { cmd, cmdsize, dataoff, datasize }, all uint32 in the slice's byte order.
#define MG_SIP_LC_CODE_SIGNATURE 0x1du

// The entitlement that already lets dyld honor DYLD_* env vars, so a binary
// carrying it is not treated as needing a patch.
static const char MG_SIP_ENT_ALLOW_DYLD[] =
	"com.apple.security.cs.allow-dyld-environment-variables";

// The on-disk patch-cache version, mirrored from pkg/local/sip.go's
// sipCacheVersion. Namespacing the cache by it re-patches every entry at once on
// a mogate upgrade. Task E1 asserts the C and Go cache paths agree exactly.
static const char MG_SIP_CACHE_VERSION[] = "v1";

static uint32_t mg_sip_be32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t mg_sip_le32(const uint8_t *p) {
	return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
		((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static uint32_t mg_sip_rd32(const uint8_t *p, int big_endian) {
	return big_endian ? mg_sip_be32(p) : mg_sip_le32(p);
}

// mg_sip_slice_in_bounds validates [offset, offset+size) falls within a
// total-byte buffer, computing in 64-bit so offset+size cannot wrap. Mirrors
// extractFatSlice's guard.
static int mg_sip_slice_in_bounds(uint64_t offset, uint64_t size, uint64_t total) {
	uint64_t end = offset + size;
	if (end < offset) {
		return 0;
	}
	if (end > total) {
		return 0;
	}
	return 1;
}

// mg_sip_is_plain_arm64 reports whether cputype/subtype identify an arm64 slice
// that is not arm64e. dyld enforces pointer authentication on arm64e and will
// not relax DYLD_INSERT_LIBRARIES there, so such slices are not injectable.
static int mg_sip_is_plain_arm64(uint32_t cputype, uint32_t subtype) {
	return cputype == MG_SIP_CPU_TYPE_ARM64 &&
		(subtype & 0xffu) != MG_SIP_CPU_SUBTYPE_ARM64E;
}

// mg_sip_is_macho reports whether data begins with a thin or fat Mach-O magic.
// Mirrors isMachO: fat/fat64 are big-endian; thin may be either byte order.
static int mg_sip_is_macho(const uint8_t *data, size_t len) {
	if (len < 4) {
		return 0;
	}
	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_FAT_MAGIC || be == MG_SIP_FAT_MAGIC_64) {
		return 1;
	}
	uint32_t le = mg_sip_le32(data);
	if (le == MG_SIP_MH_MAGIC || le == MG_SIP_MH_MAGIC_64) {
		return 1;
	}
	if (be == MG_SIP_MH_MAGIC || be == MG_SIP_MH_MAGIC_64) {
		return 1;
	}
	return 0;
}

// mg_sip_thin_header classifies a thin Mach-O header: it sets *big_endian to the
// slice's byte order and *is64 to whether it is a 64-bit (mach_header_64) image,
// returning 1 on a recognized thin magic and 0 otherwise.
static int mg_sip_thin_header(const uint8_t *data, size_t len, int *big_endian, int *is64) {
	if (len < 4) {
		return 0;
	}
	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_MH_MAGIC || be == MG_SIP_MH_MAGIC_64) {
		*big_endian = 1;
		*is64 = (be == MG_SIP_MH_MAGIC_64);
		return 1;
	}
	uint32_t le = mg_sip_le32(data);
	if (le == MG_SIP_MH_MAGIC || le == MG_SIP_MH_MAGIC_64) {
		*big_endian = 0;
		*is64 = (le == MG_SIP_MH_MAGIC_64);
		return 1;
	}
	return 0;
}

// mg_sip_thin_header_size returns the byte size of a thin Mach-O header:
// mach_header (28) or mach_header_64 (32). Load commands follow it.
static size_t mg_sip_thin_header_size(int is64) {
	return is64 ? 32u : 28u;
}

// mg_sip_choose_slice selects a slice of a (possibly fat) Mach-O that dyld can
// load with DYLD_INSERT_LIBRARIES honored: a plain-arm64 slice is preferred
// (native injector), else x86_64 under Rosetta, else none. On success it sets
// *out_off/*out_size to the chosen slice's byte range within data, *out_is_rosetta
// to 1 for an x86_64/Rosetta slice or 0 for native, and returns a pointer into
// data at the slice start (which the caller must NOT free). It returns NULL on
// an arm64e-only binary (ErrNoInjectableSlice), a malformed/out-of-bounds
// header, or a bad argument. Mirrors chooseSlice.
static char *mg_sip_choose_slice(const uint8_t *data, size_t len,
	size_t *out_off, size_t *out_size, int *out_is_rosetta) {
	if (!data || !out_off || !out_size || !out_is_rosetta || len < 4) {
		return NULL;
	}

	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_FAT_MAGIC) {
		// 32-bit fat header: { magic, nfat_arch } then nfat_arch fat_arch
		// entries { cputype, cpusubtype, offset, size, align }, each 20 bytes,
		// all big-endian. (A fat64 header is treated as non-fat, like Go, and
		// falls through to the thin path where it fails to parse -> NULL.)
		if (len < 8) {
			return NULL;
		}
		uint32_t nfat = mg_sip_be32(data + 4);
		size_t x86_off = 0;
		size_t x86_size = 0;
		int have_x86 = 0;
		for (uint32_t i = 0; i < nfat; i++) {
			size_t entry = 8 + (size_t)i * 20u;
			if (entry + 20u > len) {
				return NULL;
			}
			uint32_t cputype = mg_sip_be32(data + entry);
			uint32_t subtype = mg_sip_be32(data + entry + 4);
			uint32_t offset = mg_sip_be32(data + entry + 8);
			uint32_t size = mg_sip_be32(data + entry + 12);
			if (mg_sip_is_plain_arm64(cputype, subtype)) {
				if (!mg_sip_slice_in_bounds(offset, size, len)) {
					return NULL;
				}
				*out_off = offset;
				*out_size = size;
				*out_is_rosetta = 0;
				return (char *)(uintptr_t)(data + offset);
			}
			if (cputype == MG_SIP_CPU_TYPE_X86_64 && !have_x86) {
				have_x86 = 1;
				x86_off = offset;
				x86_size = size;
			}
		}
		if (have_x86) {
			if (!mg_sip_slice_in_bounds(x86_off, x86_size, len)) {
				return NULL;
			}
			*out_off = x86_off;
			*out_size = x86_size;
			*out_is_rosetta = 1;
			return (char *)(uintptr_t)(data + x86_off);
		}
		return NULL;
	}

	// Thin Mach-O: choose the whole file if its single arch is injectable.
	int big_endian = 0;
	int is64 = 0;
	if (!mg_sip_thin_header(data, len, &big_endian, &is64)) {
		return NULL;
	}
	if (len < mg_sip_thin_header_size(is64)) {
		return NULL;
	}
	uint32_t cputype = mg_sip_rd32(data + 4, big_endian);
	uint32_t subtype = mg_sip_rd32(data + 8, big_endian);
	if (mg_sip_is_plain_arm64(cputype, subtype)) {
		*out_off = 0;
		*out_size = len;
		*out_is_rosetta = 0;
		return (char *)(uintptr_t)data;
	}
	if (cputype == MG_SIP_CPU_TYPE_X86_64) {
		*out_off = 0;
		*out_size = len;
		*out_is_rosetta = 1;
		return (char *)(uintptr_t)data;
	}
	return NULL;
}

// mg_sip_find_lc_code_sig scans one thin Mach-O slice's load commands for
// LC_CODE_SIGNATURE, returning 1 and setting *out_dataoff/*out_datasize (both
// relative to the slice's start) when found, 0 when the slice parses but has no
// signature, and -1 on a malformed/truncated header. Mirrors codeSignatureLoad.
static int mg_sip_find_lc_code_sig(const uint8_t *slice, size_t slice_len,
	uint32_t *out_dataoff, uint32_t *out_datasize) {
	int big_endian = 0;
	int is64 = 0;
	if (!mg_sip_thin_header(slice, slice_len, &big_endian, &is64)) {
		return -1;
	}
	size_t header = mg_sip_thin_header_size(is64);
	if (slice_len < header) {
		return -1;
	}
	uint32_t ncmds = mg_sip_rd32(slice + 16, big_endian);
	size_t pos = header;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (pos + 8u > slice_len) {
			return -1;
		}
		uint32_t cmd = mg_sip_rd32(slice + pos, big_endian);
		uint32_t cmdsize = mg_sip_rd32(slice + pos + 4, big_endian);
		if (cmdsize < 8u || pos + cmdsize > slice_len) {
			return -1;
		}
		if (cmd == MG_SIP_LC_CODE_SIGNATURE) {
			if (cmdsize < 16u) {
				return -1;
			}
			*out_dataoff = mg_sip_rd32(slice + pos + 8, big_endian);
			*out_datasize = mg_sip_rd32(slice + pos + 12, big_endian);
			return 1;
		}
		pos += cmdsize;
	}
	return 0;
}

// mg_sip_first_code_signature returns the absolute file offset and size of the
// code-signature blob of the first slice that carries one: 1 and sets
// *out_off/*out_size when found, 0 when no slice has a signature, -1 on a
// malformed image. For a fat binary the offset is arch.offset + the slice's own
// dataoff (dataoff is slice-relative). Mirrors firstCodeSignature.
static int mg_sip_first_code_signature(const uint8_t *data, size_t len,
	uint32_t *out_off, uint32_t *out_size) {
	if (len < 4) {
		return -1;
	}
	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_FAT_MAGIC) {
		if (len < 8) {
			return -1;
		}
		uint32_t nfat = mg_sip_be32(data + 4);
		for (uint32_t i = 0; i < nfat; i++) {
			size_t entry = 8 + (size_t)i * 20u;
			if (entry + 20u > len) {
				return -1;
			}
			uint32_t offset = mg_sip_be32(data + entry + 8);
			uint32_t size = mg_sip_be32(data + entry + 12);
			if (!mg_sip_slice_in_bounds(offset, size, len)) {
				return -1;
			}
			uint32_t dataoff = 0;
			uint32_t datasize = 0;
			int rc = mg_sip_find_lc_code_sig(data + offset, size, &dataoff, &datasize);
			if (rc < 0) {
				return -1;
			}
			if (rc == 1) {
				uint64_t absolute = (uint64_t)offset + (uint64_t)dataoff;
				if (absolute > 0xffffffffULL) {
					return -1;
				}
				*out_off = (uint32_t)absolute;
				*out_size = datasize;
				return 1;
			}
		}
		return 0;
	}

	int big_endian = 0;
	int is64 = 0;
	if (!mg_sip_thin_header(data, len, &big_endian, &is64)) {
		return -1;
	}
	uint32_t dataoff = 0;
	uint32_t datasize = 0;
	int rc = mg_sip_find_lc_code_sig(data, len, &dataoff, &datasize);
	if (rc < 0) {
		return -1;
	}
	if (rc == 0) {
		return 0;
	}
	*out_off = dataoff;
	*out_size = datasize;
	return 1;
}

// mg_sip_contains reports whether haystack contains needle (a raw byte search;
// needle need not be NUL-terminated in haystack). Mirrors bytes.Contains.
static int mg_sip_contains(const uint8_t *haystack, size_t haystack_len,
	const char *needle, size_t needle_len) {
	if (needle_len == 0) {
		return 1;
	}
	if (haystack_len < needle_len) {
		return 0;
	}
	for (size_t i = 0; i + needle_len <= haystack_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0) {
			return 1;
		}
	}
	return 0;
}

// mg_sip_code_directory_flags reads the big-endian flags field (offset 12) of a
// CodeDirectory blob (magic csMagicCodeDirectory). Returns 0 on success, -1 on a
// too-small blob or wrong magic. Mirrors codeDirectoryFlags.
static int mg_sip_code_directory_flags(const uint8_t *blob, size_t len, uint32_t *out_flags) {
	if (len < 16) {
		return -1;
	}
	if (mg_sip_be32(blob) != MG_SIP_CS_MAGIC_CODEDIR) {
		return -1;
	}
	*out_flags = mg_sip_be32(blob + 12);
	return 0;
}

// mg_sip_parse_superblob walks a CS SuperBlob's index (magic
// csMagicEmbeddedSignature), setting *out_flags to the CodeDirectory flags and
// *out_has_dyld to whether the entitlements blob carries the allow-dyld
// entitlement. Returns 0 on success, -1 on any malformed field. All CS fields
// are big-endian. Mirrors parseCSSuperBlob.
static int mg_sip_parse_superblob(const uint8_t *blob, size_t blob_len,
	uint32_t *out_flags, int *out_has_dyld) {
	*out_flags = 0;
	*out_has_dyld = 0;
	if (blob_len < 12) {
		return -1;
	}
	if (mg_sip_be32(blob) != MG_SIP_CS_MAGIC_EMBEDDED) {
		return -1;
	}
	uint32_t count = mg_sip_be32(blob + 8);
	if (count > MG_SIP_CS_MAX_BLOB_COUNT) {
		return -1;
	}
	for (uint32_t i = 0; i < count; i++) {
		size_t entry_off = 12 + (size_t)i * MG_SIP_CS_BLOB_INDEX_SIZE;
		if (entry_off + MG_SIP_CS_BLOB_INDEX_SIZE > blob_len) {
			return -1;
		}
		uint32_t slot_type = mg_sip_be32(blob + entry_off);
		uint32_t slot_offset = mg_sip_be32(blob + entry_off + 4);
		if ((size_t)slot_offset > blob_len) {
			return -1;
		}
		if (slot_type == MG_SIP_CS_SLOT_CODEDIR) {
			uint32_t flags = 0;
			if (mg_sip_code_directory_flags(blob + slot_offset, blob_len - slot_offset, &flags) < 0) {
				return -1;
			}
			*out_flags = flags;
		} else if (slot_type == MG_SIP_CS_SLOT_ENTITLEMENTS) {
			if (mg_sip_contains(blob + slot_offset, blob_len - slot_offset,
				MG_SIP_ENT_ALLOW_DYLD, sizeof(MG_SIP_ENT_ALLOW_DYLD) - 1)) {
				*out_has_dyld = 1;
			}
		}
	}
	return 0;
}

// mg_sip_code_signature_flags returns the CodeDirectory flags of the first
// signed slice and whether the allow-dyld entitlement is present. Returns 0 on
// success (with flags 0 / has_dyld 0 for an unsigned binary) and -1 on a
// malformed image or out-of-bounds signature. Mirrors codeSignatureFlags.
static int mg_sip_code_signature_flags(const uint8_t *data, size_t len,
	uint32_t *out_flags, int *out_has_dyld) {
	*out_flags = 0;
	*out_has_dyld = 0;
	uint32_t sig_off = 0;
	uint32_t sig_size = 0;
	int rc = mg_sip_first_code_signature(data, len, &sig_off, &sig_size);
	if (rc < 0) {
		return -1;
	}
	if (rc == 0) {
		return 0;
	}
	if ((uint64_t)sig_off + (uint64_t)sig_size > (uint64_t)len) {
		return -1;
	}
	return mg_sip_parse_superblob(data + sig_off, sig_size, out_flags, out_has_dyld);
}

// mg_sip_read_file reads the whole file at path into a freshly malloc'd buffer,
// setting *out_len to its size, or returns NULL on any error. The caller owns
// and must free the buffer.
static uint8_t *mg_sip_read_file(const char *path, size_t *out_len) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}
	struct stat st;
	if (fstat(fd, &st) != 0 || st.st_size < 0) {
		close(fd);
		return NULL;
	}
	size_t size = (size_t)st.st_size;
	uint8_t *buffer = (uint8_t *)malloc(size ? size : 1);
	if (!buffer) {
		close(fd);
		return NULL;
	}
	size_t got = 0;
	while (got < size) {
		ssize_t n = read(fd, buffer + got, size - got);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			free(buffer);
			close(fd);
			return NULL;
		}
		if (n == 0) {
			break; // shrunk under us; report what we read
		}
		got += (size_t)n;
	}
	close(fd);
	*out_len = got;
	return buffer;
}

// mg_sip_needs_patch reports whether path is a restricted Mach-O whose execution
// would ignore DYLD_INSERT_LIBRARIES: 1 restricted, 0 not (including scripts and
// non-Mach-O files), -1 on error. Mirrors needsSIPPatch: a binary is restricted
// if it carries SF_RESTRICTED or a CS RESTRICT/RUNTIME flag, unless it already
// holds the allow-dyld entitlement.
static int mg_sip_needs_patch(const char *path) {
	if (!path) {
		return -1;
	}
	struct stat st;
	if (stat(path, &st) != 0) {
		return -1;
	}
	int restricted_flag = (st.st_flags & MG_SIP_SF_RESTRICTED) != 0;

	size_t len = 0;
	uint8_t *data = mg_sip_read_file(path, &len);
	if (!data) {
		return -1;
	}
	if (!mg_sip_is_macho(data, len)) {
		free(data);
		return 0;
	}
	uint32_t cs_flags = 0;
	int has_dyld = 0;
	int rc = mg_sip_code_signature_flags(data, len, &cs_flags, &has_dyld);
	free(data);
	if (rc < 0) {
		return -1;
	}
	int restricted = restricted_flag ||
		(cs_flags & (MG_SIP_CS_RESTRICT | MG_SIP_CS_RUNTIME)) != 0;
	return (restricted && !has_dyld) ? 1 : 0;
}

// mg_sip_error holds the last unrecoverable error from mg_sip_patch. It is
// thread-local so one thread of a multi-threaded target cannot observe another
// thread's error, and (like every symbol here) static, so each translation unit
// that includes this header gets its own copy. mg_sip_patch clears it on entry
// so the D1 exec detour can tell its three outcomes apart: a non-NULL return is
// the patched path; NULL with an empty last-error means "no patch needed" (run
// the original); NULL with a non-empty last-error is a hard failure the detour
// turns into a failed exec.
static __thread char mg_sip_error[512];

// mg_sip_last_error returns the current thread's last error string, or an empty
// string when the last mg_sip_patch call needed no patch or succeeded. The
// pointer is owned by the thread-local buffer: the caller must not free it and
// should copy it before the next mg_sip_patch call.
static const char *mg_sip_last_error(void) {
	return mg_sip_error;
}

// mg_sip_set_error records msg as the current thread's last error, truncating to
// the fixed buffer (the string is diagnostic, not load-bearing).
static void mg_sip_set_error(const char *msg) {
	size_t n = strlen(msg);
	if (n >= sizeof(mg_sip_error)) {
		n = sizeof(mg_sip_error) - 1;
	}
	memcpy(mg_sip_error, msg, n);
	mg_sip_error[n] = 0;
}

// mg_sip_is_space reports whether c is one of the ASCII whitespace characters
// unicode.IsSpace recognizes, so the shebang tokenizer splits exactly where
// Go's strings.Fields would.
static int mg_sip_is_space(char c) {
	return c == ' ' || c == '\t' || c == '\n' ||
		c == '\v' || c == '\f' || c == '\r';
}

// mg_sip_read_shebang_line reads the first line of the file at path into buf
// (capacity buf_cap; the caller sizes it, conventionally 8192 like readShebang's
// scanner), stopping at the first newline, at EOF, or when buf fills. It sets
// *out_got to the number of bytes read and returns 0 on success or -1 on an
// open/read error. The buffer is not NUL-terminated; callers use *out_got.
static int mg_sip_read_shebang_line(const char *path, char *buf, size_t buf_cap, size_t *out_got) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	size_t got = 0;
	while (got < buf_cap) {
		ssize_t n = read(fd, buf + got, buf_cap - got);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			close(fd);
			return -1;
		}
		if (n == 0) {
			break; // EOF before a newline
		}
		got += (size_t)n;
		if (memchr(buf, '\n', got) != NULL) {
			break;
		}
	}
	close(fd);
	*out_got = got;
	return 0;
}

// mg_sip_parse_shebang parses the first-line buffer buf[0..got) for a
// "#!interp [args...]" shebang, mirroring Go's readShebang (which splits with
// strings.Fields). On a shebang it copies the interpreter token into interp
// (capacity interp_cap, NUL-terminated) and, when out_args is non-NULL, sets
// *out_args to a freshly malloc'd NULL-terminated array of the remaining
// whitespace-separated fields (a {NULL}-only array when there are none), which
// the caller frees via mg_sip_free_strv. It returns 1 on a shebang, 0 when buf
// is not a shebang (no "#!" prefix, empty, or "#!" with no interpreter token),
// and -1 when the interpreter does not fit interp_cap or an allocation fails.
// On a 0/-1 return *out_args is left NULL.
static int mg_sip_parse_shebang(const char *buf, size_t got, char *interp,
	size_t interp_cap, char ***out_args) {
	if (out_args) {
		*out_args = NULL;
	}
	if (got < 2 || buf[0] != '#' || buf[1] != '!') {
		return 0; // not a shebang (covers Mach-O and other binaries)
	}
	size_t line_len = got;
	const char *nl = (const char *)memchr(buf, '\n', got);
	if (nl != NULL) {
		line_len = (size_t)(nl - buf);
	}
	size_t i = 2;
	while (i < line_len && mg_sip_is_space(buf[i])) {
		i++;
	}
	size_t start = i;
	while (i < line_len && !mg_sip_is_space(buf[i])) {
		i++;
	}
	size_t token = i - start;
	if (token == 0) {
		return 0; // "#!" with no interpreter is not a shebang (readShebang ok=false)
	}
	if (token >= interp_cap) {
		return -1; // interpreter path does not fit
	}
	memcpy(interp, buf + start, token);
	interp[token] = 0;
	if (!out_args) {
		return 1;
	}
	// Tokenize the remaining fields exactly as strings.Fields would: two passes
	// (count, then fill) over [i, line_len) splitting on whitespace runs.
	size_t count = 0;
	for (size_t j = i; j < line_len;) {
		while (j < line_len && mg_sip_is_space(buf[j])) {
			j++;
		}
		if (j >= line_len) {
			break;
		}
		while (j < line_len && !mg_sip_is_space(buf[j])) {
			j++;
		}
		count++;
	}
	char **args = (char **)malloc((count + 1) * sizeof(char *));
	if (!args) {
		return -1;
	}
	size_t w = 0;
	for (size_t j = i; j < line_len && w < count;) {
		while (j < line_len && mg_sip_is_space(buf[j])) {
			j++;
		}
		if (j >= line_len) {
			break;
		}
		size_t s = j;
		while (j < line_len && !mg_sip_is_space(buf[j])) {
			j++;
		}
		size_t tlen = j - s;
		char *tok = (char *)malloc(tlen + 1);
		if (!tok) {
			for (size_t k = 0; k < w; k++) {
				free(args[k]);
			}
			free(args);
			return -1;
		}
		memcpy(tok, buf + s, tlen);
		tok[tlen] = 0;
		args[w++] = tok;
	}
	args[w] = NULL;
	*out_args = args;
	return 1;
}

// mg_sip_read_shebang reads the first line of the file at path and, when it is a
// "#!interp [args...]" shebang, copies the interpreter token into out (capacity
// out_cap, NUL-terminated) and returns 1. It returns 0 when the file is not a
// shebang (no "#!" prefix, an empty file, or "#!" with no interpreter token) and
// -1 on an I/O error or an interpreter too long for out. Mirrors readShebang;
// mg_sip_patch uses only the interpreter, so the argument fields are discarded.
static int mg_sip_read_shebang(const char *path, char *out, size_t out_cap) {
	char buf[8192];
	size_t got = 0;
	if (mg_sip_read_shebang_line(path, buf, sizeof(buf), &got) != 0) {
		return -1;
	}
	return mg_sip_parse_shebang(buf, got, out, out_cap, NULL);
}

// mg_sip_read_shebang_fields is mg_sip_read_shebang plus the shebang's argument
// fields: on a shebang it returns 1 with *out_args set to a malloc'd
// NULL-terminated array (freed via mg_sip_free_strv); the D1 exec detour rebuilds
// a script's argv as [interp, args..., scriptPath, origArgv[1:]...].
static int mg_sip_read_shebang_fields(const char *path, char *interp,
	size_t interp_cap, char ***out_args) {
	char buf[8192];
	size_t got = 0;
	if (out_args) {
		*out_args = NULL;
	}
	if (mg_sip_read_shebang_line(path, buf, sizeof(buf), &got) != 0) {
		return -1;
	}
	return mg_sip_parse_shebang(buf, got, interp, interp_cap, out_args);
}

// mg_sip_lexical_clean returns a freshly malloc'd, lexically cleaned copy of
// path (collapsing "." / ".." / redundant separators without touching the
// filesystem), mirroring Go's path/filepath.Clean so the cache path matches the
// Go port byte-for-byte. The caller owns the result.
static char *mg_sip_lexical_clean(const char *path) {
	size_t n = strlen(path);
	char *out = (char *)malloc(n + 2);
	if (!out) {
		return NULL;
	}
	if (n == 0) {
		out[0] = '.';
		out[1] = 0;
		return out;
	}
	int rooted = path[0] == '/';
	size_t w = 0;
	size_t r = 0;
	size_t dotdot = 0;
	if (rooted) {
		out[w++] = '/';
		r = 1;
		dotdot = 1;
	}
	while (r < n) {
		if (path[r] == '/') {
			r++;
		} else if (path[r] == '.' && (r + 1 == n || path[r + 1] == '/')) {
			r++;
		} else if (path[r] == '.' && path[r + 1] == '.' &&
			(r + 2 == n || path[r + 2] == '/')) {
			r += 2;
			if (w > dotdot) {
				w--;
				while (w > dotdot && out[w - 1] != '/') {
					w--;
				}
			} else if (!rooted) {
				if (w > 0) {
					out[w++] = '/';
				}
				out[w++] = '.';
				out[w++] = '.';
				dotdot = w;
			}
		} else {
			if ((rooted && w != 1) || (!rooted && w != 0)) {
				out[w++] = '/';
			}
			while (r < n && path[r] != '/') {
				out[w++] = path[r++];
			}
		}
	}
	if (w == 0) {
		out[w++] = '.';
	}
	out[w] = 0;
	return out;
}

// mg_sip_abs_clean returns a freshly malloc'd absolute, lexically cleaned copy of
// path: a relative path is joined onto the current working directory first,
// mirroring Go's filepath.Abs. The caller owns the result; NULL on error.
static char *mg_sip_abs_clean(const char *path) {
	if (path[0] == '/') {
		return mg_sip_lexical_clean(path);
	}
	char cwd[PATH_MAX];
	if (!getcwd(cwd, sizeof(cwd))) {
		return NULL;
	}
	size_t need = strlen(cwd) + 1 + strlen(path) + 1;
	char *joined = (char *)malloc(need);
	if (!joined) {
		return NULL;
	}
	snprintf(joined, need, "%s/%s", cwd, path);
	char *cleaned = mg_sip_lexical_clean(joined);
	free(joined);
	return cleaned;
}

// mg_sip_cache_path returns the on-disk cache path for the patched copy of path:
// <HOME>/Library/Caches/mogate/sip/<MG_SIP_CACHE_VERSION>/<abs(path) without its
// leading '/'>. It mirrors pkg/local/sip.go's sipCachePath (os.UserCacheDir on
// darwin is $HOME/Library/Caches); the assembled path is lexically cleaned so it
// matches Go's filepath.Join. Returns a malloc'd string the caller owns, or NULL.
static char *mg_sip_cache_path(const char *path) {
	const char *home = getenv("HOME");
	if (!home || !*home) {
		return NULL;
	}
	char *cleaned = mg_sip_abs_clean(path);
	if (!cleaned) {
		return NULL;
	}
	const char *rel = cleaned;
	if (rel[0] == '/') {
		rel++; // TrimPrefix a single leading separator, like the Go port
	}
	static const char mid[] = "/Library/Caches/mogate/sip/";
	size_t need = strlen(home) + (sizeof(mid) - 1) +
		(sizeof(MG_SIP_CACHE_VERSION) - 1) + 1 + strlen(rel) + 1;
	char *joined = (char *)malloc(need);
	if (!joined) {
		free(cleaned);
		return NULL;
	}
	snprintf(joined, need, "%s%s%s/%s", home, mid, MG_SIP_CACHE_VERSION, rel);
	free(cleaned);
	char *out = mg_sip_lexical_clean(joined);
	free(joined);
	return out;
}

// mg_sip_mkdir_parents creates dir and every missing parent with mode 0700,
// mirroring os.MkdirAll(dir, 0700). It temporarily rewrites separators in dir to
// NUL while walking the components and restores them before returning. Returns 0
// on success (including when a component already exists) and -1 otherwise.
static int mg_sip_mkdir_parents(char *dir) {
	for (char *p = dir + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			int rc = mkdir(dir, 0700);
			*p = '/';
			if (rc != 0 && errno != EEXIST) {
				return -1;
			}
		}
	}
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		return -1;
	}
	return 0;
}

// mg_sip_write_all writes size bytes from data to fd, retrying short writes and
// EINTR. Returns 0 on success, -1 on error.
static int mg_sip_write_all(int fd, const uint8_t *data, size_t size) {
	size_t off = 0;
	while (off < size) {
		ssize_t n = write(fd, data + off, size - off);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

// mg_sip_run_codesign spawns /usr/bin/codesign with argv via the real
// posix_spawn (D1 adds the exec hooks and D2 the reentrancy guard; C2 predates
// both, so this is a plain unhooked spawn) and waits for it. It returns 0 with
// the child's exit status in *out_exit, or -1 if the spawn, the wait, or the
// child (killed by a signal) failed.
static int mg_sip_run_codesign(char *const argv[], int *out_exit) {
	pid_t pid = 0;
	char **envp = *_NSGetEnviron();
	int rc = posix_spawn(&pid, "/usr/bin/codesign", NULL, NULL, argv, envp);
	if (rc != 0) {
		errno = rc;
		return -1;
	}
	int status = 0;
	for (;;) {
		if (waitpid(pid, &status, 0) >= 0) {
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		return -1;
	}
	if (!WIFEXITED(status)) {
		return -1;
	}
	*out_exit = WEXITSTATUS(status);
	return 0;
}

// mg_sip_adhoc_resign strips path's signature and replaces it with an ad-hoc
// one, so dyld stops enforcing the restrictions (library validation, hardened
// runtime) that would otherwise make it ignore DYLD_INSERT_LIBRARIES for this
// copy. Mirrors adhocResign: --remove-signature may exit non-zero on an already
// unsigned slice ("object is not signed at all"), a harmless no-op whose result
// is deliberately ignored; only the "-s - -f" ad-hoc sign must succeed. Returns 0
// on success, -1 on a spawn/wait failure or a non-zero codesign exit.
static int mg_sip_adhoc_resign(const char *path) {
	int exit_code = 0;
	char *remove_argv[] = {
		(char *)"/usr/bin/codesign", (char *)"--remove-signature",
		(char *)path, NULL,
	};
	(void)mg_sip_run_codesign(remove_argv, &exit_code);

	char *sign_argv[] = {
		(char *)"/usr/bin/codesign", (char *)"-s", (char *)"-",
		(char *)"-f", (char *)path, NULL,
	};
	exit_code = 0;
	if (mg_sip_run_codesign(sign_argv, &exit_code) != 0) {
		return -1;
	}
	if (exit_code != 0) {
		return -1;
	}
	return 0;
}

// mg_sip_patch makes path loadable with DYLD_INSERT_LIBRARIES honored and returns
// a newly malloc'd path to the executable to run (the caller frees), or NULL. The
// NULL return is overloaded and disambiguated by mg_sip_last_error, which
// mg_sip_patch clears on entry: NULL with an empty last-error means "no patch
// needed" (run path unchanged); NULL with a non-empty last-error is a hard
// failure the D1 exec detour turns into a failed exec. Mirrors patchIfRestricted:
//   1. A "#!" script patches its interpreter recursively (an interpreter can
//      itself be restricted, e.g. /bin/bash) and returns that result; the D1
//      detour re-derives argv from the shebang.
//   2. An unrestricted binary needs no patch -> NULL, empty error.
//   3. A restricted binary already in the cache is reused.
//   4. Otherwise it is thinned to an injectable slice, written to a temp file in
//      the cache dir, ad-hoc re-signed, and atomically renamed into place. The
//      original binary is never modified.
static char *mg_sip_patch(const char *path) {
	mg_sip_error[0] = 0;
	if (!path) {
		mg_sip_set_error("sip: null path");
		return NULL;
	}

	char interp[PATH_MAX];
	int shebang = mg_sip_read_shebang(path, interp, sizeof(interp));
	if (shebang < 0) {
		mg_sip_set_error("sip: read shebang");
		return NULL;
	}
	if (shebang == 1) {
		return mg_sip_patch(interp); // single-level recursion, like the Go port
	}

	int need = mg_sip_needs_patch(path);
	if (need < 0) {
		mg_sip_set_error("sip: needs-patch check");
		return NULL;
	}
	if (need == 0) {
		return NULL; // no patch needed; last-error stays empty
	}

	char *cache = mg_sip_cache_path(path);
	if (!cache) {
		mg_sip_set_error("sip: cache path");
		return NULL;
	}
	if (access(cache, F_OK) == 0) {
		return cache; // reuse a prior patch
	}

	char *dir = NULL;
	char *tmpl = NULL;
	uint8_t *data = NULL;
	int tfd = -1;
	int tmp_created = 0;

	size_t len = 0;
	data = mg_sip_read_file(path, &len);
	if (!data) {
		mg_sip_set_error("sip: read file");
		goto fail;
	}

	size_t off = 0;
	size_t size = 0;
	int rosetta = 0;
	char *slice = mg_sip_choose_slice(data, len, &off, &size, &rosetta);
	if (!slice) {
		mg_sip_set_error("sip: no injectable slice");
		goto fail;
	}

	const char *last = strrchr(cache, '/');
	if (!last) {
		mg_sip_set_error("sip: bad cache path");
		goto fail;
	}
	size_t dir_len = (size_t)(last - cache);
	dir = (char *)malloc(dir_len + 1);
	if (!dir) {
		mg_sip_set_error("sip: out of memory");
		goto fail;
	}
	memcpy(dir, cache, dir_len);
	dir[dir_len] = 0;
	if (mg_sip_mkdir_parents(dir) != 0) {
		mg_sip_set_error("sip: mkdir cache dir");
		goto fail;
	}

	static const char suffix[] = "/.sip-XXXXXX";
	size_t tmpl_len = dir_len + sizeof(suffix); // sizeof includes the NUL
	tmpl = (char *)malloc(tmpl_len);
	if (!tmpl) {
		mg_sip_set_error("sip: out of memory");
		goto fail;
	}
	snprintf(tmpl, tmpl_len, "%s%s", dir, suffix);
	tfd = mkstemp(tmpl);
	if (tfd < 0) {
		mg_sip_set_error("sip: create temp file");
		goto fail;
	}
	tmp_created = 1;

	if (mg_sip_write_all(tfd, (const uint8_t *)slice, size) != 0) {
		mg_sip_set_error("sip: write slice");
		goto fail;
	}
	if (fchmod(tfd, 0700) != 0) {
		mg_sip_set_error("sip: chmod temp file");
		goto fail;
	}
	if (close(tfd) != 0) {
		tfd = -1;
		mg_sip_set_error("sip: close temp file");
		goto fail;
	}
	tfd = -1;

	if (mg_sip_adhoc_resign(tmpl) != 0) {
		mg_sip_set_error("sip: ad-hoc re-sign");
		goto fail;
	}
	if (rename(tmpl, cache) != 0) {
		mg_sip_set_error("sip: rename into cache");
		goto fail;
	}
	tmp_created = 0;

	free(tmpl);
	free(dir);
	free(data);
	return cache; // caller frees

fail:
	if (tfd >= 0) {
		close(tfd);
	}
	if (tmp_created) {
		unlink(tmpl);
	}
	free(tmpl);
	free(dir);
	free(data);
	free(cache);
	return NULL;
}

// ---------------------------------------------------------------------------
// D1: exec-family detours.
//
// When an injected process spawns a child, the child must itself keep the
// injection: its executable is SIP-patched (so dyld honors
// DYLD_INSERT_LIBRARIES for it) and its environment retains
// DYLD_INSERT_LIBRARIES=<injector> and MOGATE_SOCKET=<socket> so the injector
// re-loads and re-connects the child. The substantive logic lives here as
// static functions so the two-TU cgo bridge can test it without replacing the
// process; injector/main.go's mg_execve_hook / mg_posix_spawn_hook etc. are thin
// interpose wrappers that pass in the resolved real exec function (the test
// passes a recording spy). Everything is __APPLE__-only: exec is not SIP-hooked
// on linux, which has no System Integrity Protection.
// ---------------------------------------------------------------------------

// Upper bounds guarding argv/envp construction against a hostile or corrupt
// caller: neither a shebang line's fields nor an environment realistically
// approaches these, and they keep the count/size math below from overflowing.
#define MG_SIP_MAX_ARGS 65536u
#define MG_SIP_MAX_ENV 262144u

// mg_sip_free_strv frees a malloc'd NULL-terminated array of malloc'd strings
// (used for both the fixed envp and a shebang's argument fields).
static void mg_sip_free_strv(char **v) {
	if (!v) {
		return;
	}
	for (size_t i = 0; v[i]; i++) {
		free(v[i]);
	}
	free(v);
}

// mg_sip_join2 returns a freshly malloc'd concatenation prefix+value, or NULL on
// allocation failure. Used to build "KEY=value" environment entries.
static char *mg_sip_join2(const char *prefix, const char *value) {
	size_t pl = strlen(prefix);
	size_t vl = strlen(value);
	char *out = (char *)malloc(pl + vl + 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, prefix, pl);
	memcpy(out + pl, value, vl);
	out[pl + vl] = 0;
	return out;
}

// mg_sip_pathlist_has reports whether the ':'-delimited list contains elem as an
// exact element, so re-adding the injector to DYLD_INSERT_LIBRARIES does not
// duplicate a path a child already inherited.
static int mg_sip_pathlist_has(const char *list, const char *elem) {
	size_t el = strlen(elem);
	if (el == 0) {
		return 1;
	}
	const char *p = list;
	for (;;) {
		const char *colon = strchr(p, ':');
		size_t seg = colon ? (size_t)(colon - p) : strlen(p);
		if (seg == el && memcmp(p, elem, el) == 0) {
			return 1;
		}
		if (!colon) {
			break;
		}
		p = colon + 1;
	}
	return 0;
}

// mg_sip_dyld_entry returns a malloc'd "DYLD_INSERT_LIBRARIES=" entry that is
// guaranteed to list self: existing is kept unchanged when it already contains
// self, otherwise self is prepended (self alone when existing is empty). Prepend
// order mirrors Go's injectedEnvironment (the injector's own path first). Returns
// NULL on allocation failure.
static char *mg_sip_dyld_entry(const char *existing, const char *self) {
	static const char pfx[] = "DYLD_INSERT_LIBRARIES=";
	size_t pl = sizeof(pfx) - 1;
	if (!existing || !*existing) {
		return mg_sip_join2(pfx, self);
	}
	if (mg_sip_pathlist_has(existing, self)) {
		return mg_sip_join2(pfx, existing);
	}
	size_t sl = strlen(self);
	size_t el = strlen(existing);
	char *out = (char *)malloc(pl + sl + 1 + el + 1);
	if (!out) {
		return NULL;
	}
	memcpy(out, pfx, pl);
	memcpy(out + pl, self, sl);
	out[pl + sl] = ':';
	memcpy(out + pl + sl + 1, existing, el);
	out[pl + sl + 1 + el] = 0;
	return out;
}

// mg_sip_fix_env returns a freshly malloc'd, NULL-terminated environment that is
// a copy of envp with DYLD_INSERT_LIBRARIES ensured to list self (self may be
// NULL to skip) and MOGATE_SOCKET set to socket (socket may be NULL to skip),
// re-adding either if a caller dropped it. It replaces an existing
// MOGATE_SOCKET and augments an existing DYLD_INSERT_LIBRARIES in place so their
// position is preserved. Returns NULL on allocation failure; the caller frees
// via mg_sip_free_strv.
static char **mg_sip_fix_env(char *const envp[], const char *self, const char *socket) {
	static const char dyld_pfx[] = "DYLD_INSERT_LIBRARIES=";
	static const char sock_pfx[] = "MOGATE_SOCKET=";
	size_t n = 0;
	if (envp) {
		while (envp[n]) {
			if (n >= MG_SIP_MAX_ENV) {
				return NULL;
			}
			n++;
		}
	}
	// n entries + up to 2 appended (DYLD, MOGATE_SOCKET) + NULL terminator.
	char **out = (char **)calloc(n + 3, sizeof(char *));
	if (!out) {
		return NULL;
	}
	size_t w = 0;
	int dyld_done = 0;
	int sock_done = 0;
	for (size_t i = 0; i < n; i++) {
		const char *e = envp[i];
		char *repl;
		if (self && strncmp(e, dyld_pfx, sizeof(dyld_pfx) - 1) == 0) {
			repl = mg_sip_dyld_entry(e + sizeof(dyld_pfx) - 1, self);
			dyld_done = 1;
		} else if (socket && strncmp(e, sock_pfx, sizeof(sock_pfx) - 1) == 0) {
			repl = mg_sip_join2(sock_pfx, socket);
			sock_done = 1;
		} else {
			repl = strdup(e);
		}
		if (!repl) {
			goto oom;
		}
		out[w++] = repl;
	}
	if (self && !dyld_done) {
		char *v = mg_sip_dyld_entry(NULL, self);
		if (!v) {
			goto oom;
		}
		out[w++] = v;
	}
	if (socket && !sock_done) {
		char *v = mg_sip_join2(sock_pfx, socket);
		if (!v) {
			goto oom;
		}
		out[w++] = v;
	}
	out[w] = NULL;
	return out;
oom:
	mg_sip_free_strv(out);
	return NULL;
}

// mg_sip_path_search resolves a bare command name (no '/') against $PATH the way
// execvp / posix_spawnp do, writing the first executable regular-file match into
// out (capacity out_cap) and returning 1, or returning 0 when nothing matches or
// a candidate does not fit out. An empty PATH element means the current
// directory, and an unset/empty $PATH falls back to _CS_PATH (typically
// "/usr/bin:/bin").
static int mg_sip_path_search(const char *file, char *out, size_t out_cap) {
	if (!file || !*file) {
		return 0;
	}
	char defpath[PATH_MAX];
	const char *path = getenv("PATH");
	if (!path || !*path) {
		size_t got = confstr(_CS_PATH, defpath, sizeof(defpath));
		path = (got > 0 && got <= sizeof(defpath)) ? defpath : "/usr/bin:/bin";
	}
	size_t flen = strlen(file);
	const char *p = path;
	for (;;) {
		const char *colon = strchr(p, ':');
		const char *dir = p;
		size_t dlen = colon ? (size_t)(colon - p) : strlen(p);
		if (dlen == 0) {
			dir = "."; // an empty PATH element means the current directory
			dlen = 1;
		}
		if (dlen + 1 + flen + 1 <= out_cap) {
			memcpy(out, dir, dlen);
			out[dlen] = '/';
			memcpy(out + dlen + 1, file, flen);
			out[dlen + 1 + flen] = 0;
			struct stat st;
			if (access(out, X_OK) == 0 && stat(out, &st) == 0 && S_ISREG(st.st_mode)) {
				return 1;
			}
		}
		if (!colon) {
			break;
		}
		p = colon + 1;
	}
	return 0;
}

// mg_sip_exec_target is the resolved plan for exec'ing a path: the executable to
// actually run (path), whether the input was a "#!" script (and if so the
// original script path plus its shebang argument fields, so the detour can
// rebuild argv), and an error flag for a hard patch failure the detour must turn
// into a failed exec. All non-NULL pointer members are malloc'd; free via
// mg_sip_exec_target_free.
typedef struct {
	char *path;
	int error;
	int is_script;
	char *script_path;
	char **script_args;
} mg_sip_exec_target;

// mg_sip_exec_target_free releases every owned member of a target and zeroes it.
static void mg_sip_exec_target_free(mg_sip_exec_target *t) {
	if (!t) {
		return;
	}
	free(t->path);
	free(t->script_path);
	mg_sip_free_strv(t->script_args);
	t->path = NULL;
	t->script_path = NULL;
	t->script_args = NULL;
}

// mg_sip_resolve_exec builds the exec plan for resolved (an already
// PATH-resolved path). It reads a leading shebang and, for a script, patches the
// interpreter and records the shebang args + original path; for a plain binary
// it patches the binary. Fail-loud: a hard mg_sip_patch failure (NULL with a
// non-empty mg_sip_last_error) sets out->error so the detour refuses to exec an
// un-patched binary that needed patching. A path that is not a readable regular
// file (missing, a directory, a device) is passed through un-patched so the real
// exec reports the true errno (ENOENT/EACCES/...) rather than a synthetic one.
static void mg_sip_resolve_exec(const char *resolved, mg_sip_exec_target *out) {
	memset(out, 0, sizeof(*out));
	if (!resolved) {
		mg_sip_set_error("sip: null exec path");
		out->error = 1;
		return;
	}
	struct stat st;
	if (stat(resolved, &st) != 0 || !S_ISREG(st.st_mode)) {
		out->path = strdup(resolved);
		if (!out->path) {
			mg_sip_set_error("sip: out of memory");
			out->error = 1;
		}
		return;
	}

	char interp[PATH_MAX];
	char **args = NULL;
	int sb = mg_sip_read_shebang_fields(resolved, interp, sizeof(interp), &args);
	if (sb < 0) {
		mg_sip_set_error("sip: read shebang");
		out->error = 1;
		return;
	}
	if (sb == 1) {
		char *patched = mg_sip_patch(interp);
		if (!patched) {
			if (mg_sip_last_error()[0] != '\0') {
				mg_sip_free_strv(args);
				out->error = 1;
				return;
			}
			patched = strdup(interp); // interpreter needs no patch: run it as-is
			if (!patched) {
				mg_sip_free_strv(args);
				mg_sip_set_error("sip: out of memory");
				out->error = 1;
				return;
			}
		}
		char *script_path = strdup(resolved);
		if (!script_path) {
			free(patched);
			mg_sip_free_strv(args);
			mg_sip_set_error("sip: out of memory");
			out->error = 1;
			return;
		}
		out->path = patched;
		out->is_script = 1;
		out->script_path = script_path;
		out->script_args = args;
		return;
	}

	// Not a script: patch the binary itself.
	char *patched = mg_sip_patch(resolved);
	if (!patched) {
		if (mg_sip_last_error()[0] != '\0') {
			out->error = 1;
			return;
		}
		patched = strdup(resolved); // binary needs no patch: run it as-is
		if (!patched) {
			mg_sip_set_error("sip: out of memory");
			out->error = 1;
		}
	}
	out->path = patched;
}

// mg_sip_build_script_argv builds a child argv for a shebang script:
// [interp, shebang args..., scriptPath, origArgv[1:]...]. The returned array
// holds borrowed pointers into t and orig_argv, so the caller frees only the
// array (not its elements). Returns NULL on allocation failure or an argv longer
// than MG_SIP_MAX_ARGS.
static char **mg_sip_build_script_argv(const mg_sip_exec_target *t, char *const orig_argv[]) {
	size_t oc = 0;
	if (orig_argv) {
		while (orig_argv[oc]) {
			if (oc >= MG_SIP_MAX_ARGS) {
				return NULL;
			}
			oc++;
		}
	}
	size_t ac = 0;
	while (t->script_args[ac]) {
		if (ac >= MG_SIP_MAX_ARGS) {
			return NULL;
		}
		ac++;
	}
	size_t tail = (oc > 0) ? (oc - 1) : 0; // original argv without argv[0]
	size_t total = 1 + ac + 1 + tail; // interp + shebang args + script path + tail
	char **out = (char **)malloc((total + 1) * sizeof(char *));
	if (!out) {
		return NULL;
	}
	size_t w = 0;
	out[w++] = t->path;
	for (size_t i = 0; i < ac; i++) {
		out[w++] = t->script_args[i];
	}
	out[w++] = t->script_path;
	for (size_t i = 1; i < oc; i++) {
		out[w++] = orig_argv[i];
	}
	out[w] = NULL;
	return out;
}

// Real exec-family function types the detours ultimately call (the injector's
// resolved libSystem symbol, or the test spy). posix_spawn and posix_spawnp
// share a signature.
typedef int (*mg_sip_execve_fn)(const char *, char *const[], char *const[]);
typedef int (*mg_sip_execvp_fn)(const char *, char *const[]);
typedef int (*mg_sip_spawn_fn)(pid_t *, const char *,
	const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
	char *const[], char *const[]);

// mg_sip_execve_detour is the core execve/execvp path: resolve the exec plan for
// path, build a DYLD/MOGATE_SOCKET-preserving envp, rebuild argv for a script,
// and call real. On a hard patch failure it sets errno=ENOEXEC and returns -1
// without calling real (fail-loud). real is only reached on an execve error, so
// the frees below run on failure; on success the image is replaced.
static int mg_sip_execve_detour(const char *path, char *const argv[], char *const envp[],
	const char *self, const char *socket, mg_sip_execve_fn real) {
	mg_sip_exec_target target;
	mg_sip_resolve_exec(path, &target);
	if (target.error) {
		mg_sip_exec_target_free(&target);
		errno = ENOEXEC;
		return -1;
	}
	char **new_env = mg_sip_fix_env(envp, self, socket);
	if (!new_env) {
		mg_sip_exec_target_free(&target);
		errno = ENOMEM;
		return -1;
	}
	int rc;
	int saved;
	if (target.is_script) {
		char **new_argv = mg_sip_build_script_argv(&target, argv);
		if (!new_argv) {
			mg_sip_free_strv(new_env);
			mg_sip_exec_target_free(&target);
			errno = ENOMEM;
			return -1;
		}
		rc = real(target.path, new_argv, new_env);
		saved = errno;
		free(new_argv);
	} else {
		rc = real(target.path, argv, new_env);
		saved = errno;
	}
	mg_sip_free_strv(new_env);
	mg_sip_exec_target_free(&target);
	errno = saved;
	return rc;
}

// mg_sip_posix_spawn_detour is the core posix_spawn/posix_spawnp path. Unlike
// execve, posix_spawn returns (the child runs concurrently), so it always frees
// the built envp/argv on return and reports errors via its return value (an
// errno) rather than the errno global. A NULL envp means "use the current
// environment", matching a common caller convention.
static int mg_sip_posix_spawn_detour(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
	char *const argv[], char *const envp[],
	const char *self, const char *socket, mg_sip_spawn_fn real) {
	mg_sip_exec_target target;
	mg_sip_resolve_exec(path, &target);
	if (target.error) {
		mg_sip_exec_target_free(&target);
		return ENOEXEC;
	}
	char *const *base = envp ? envp : (char *const *)*_NSGetEnviron();
	char **new_env = mg_sip_fix_env(base, self, socket);
	if (!new_env) {
		mg_sip_exec_target_free(&target);
		return ENOMEM;
	}
	int rc;
	if (target.is_script) {
		char **new_argv = mg_sip_build_script_argv(&target, argv);
		if (!new_argv) {
			mg_sip_free_strv(new_env);
			mg_sip_exec_target_free(&target);
			return ENOMEM;
		}
		rc = real(pid, target.path, fa, attr, new_argv, new_env);
		free(new_argv);
	} else {
		rc = real(pid, target.path, fa, attr, argv, new_env);
	}
	mg_sip_free_strv(new_env);
	mg_sip_exec_target_free(&target);
	return rc;
}

// mg_sip_execvp_detour PATH-resolves a bare file name (execvp semantics) then
// runs the execve detour over the current environment. When PATH resolution
// finds nothing the bare name is passed through, so the real execve reports the
// same not-found error the caller would otherwise see.
static int mg_sip_execvp_detour(const char *file, char *const argv[],
	const char *self, const char *socket, mg_sip_execve_fn real) {
	char resolved[PATH_MAX];
	const char *target = file;
	if (file && !strchr(file, '/') && mg_sip_path_search(file, resolved, sizeof(resolved)) == 1) {
		target = resolved;
	}
	char *const *env = (char *const *)*_NSGetEnviron();
	return mg_sip_execve_detour(target, argv, env, self, socket, real);
}

// mg_sip_posix_spawnp_detour PATH-resolves a bare file name (posix_spawnp
// semantics) then runs the posix_spawn detour. real is a real posix_spawn: a
// resolved absolute target needs no further search, and an unresolved bare name
// is passed through to fail identically to the caller's expectation.
static int mg_sip_posix_spawnp_detour(pid_t *pid, const char *file,
	const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
	char *const argv[], char *const envp[],
	const char *self, const char *socket, mg_sip_spawn_fn real) {
	char resolved[PATH_MAX];
	const char *target = file;
	if (file && !strchr(file, '/') && mg_sip_path_search(file, resolved, sizeof(resolved)) == 1) {
		target = resolved;
	}
	return mg_sip_posix_spawn_detour(pid, target, fa, attr, argv, envp, self, socket, real);
}

#endif // __APPLE__

#endif // MG_SIP_DARWIN_H
