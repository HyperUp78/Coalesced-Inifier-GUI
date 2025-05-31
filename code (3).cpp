#define OEMRESOURCE
#include <windows.h>
#include <commdlg.h> // For GetOpenFileName, GetSaveFileName
#include <shlobj.h>  // For SHBrowseForFolder
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstdint>
#include <iomanip> // For hex output

// Forward declarations for Win32
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateControls(HWND hwnd);
void HandlePack(HWND hwnd);
void HandleUnpack(HWND hwnd);
std::wstring ShowOpenFileDialog(HWND hwnd, const wchar_t* filter, const wchar_t* title);
std::wstring ShowSaveFileDialog(HWND hwnd, const wchar_t* filter, const wchar_t* title, const wchar_t* defaultName);
std::wstring ShowBrowseFolderDialog(HWND hwnd, const wchar_t* title);

// --- UTF-8 / UTF-16 Conversion ---
std::wstring utf8_to_wstring(const std::string& utf8_str) {
    if (utf8_str.empty()) return std::wstring();
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), static_cast<int>(utf8_str.length()), NULL, 0);
    if (wide_len == 0) throw std::runtime_error("MultiByteToWideChar failed to get length. Error: " + std::to_string(GetLastError()));
    std::vector<wchar_t> wide_buf(wide_len);
    int result = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), static_cast<int>(utf8_str.length()), wide_buf.data(), wide_len);
    if (result == 0) throw std::runtime_error("MultiByteToWideChar failed to convert. Error: " + std::to_string(GetLastError()));
    return std::wstring(wide_buf.data(), wide_len);
}

std::string wstring_to_utf8(const std::wstring& wide_str) {
    if (wide_str.empty()) return std::string();
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), static_cast<int>(wide_str.length()), NULL, 0, NULL, NULL);
    if (utf8_len == 0) throw std::runtime_error("WideCharToMultiByte failed to get length. Error: " + std::to_string(GetLastError()));
    std::vector<char> utf8_buf(utf8_len);
    int result = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), static_cast<int>(wide_str.length()), utf8_buf.data(), utf8_len, NULL, NULL);
    if (result == 0) throw std::runtime_error("WideCharToMultiByte failed to convert. Error: " + std::to_string(GetLastError()));
    return std::string(utf8_buf.data(), utf8_len);
}

// --- Path Utilities ---
std::string replace_all_str(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); 
    }
    return str;
}

std::wstring replace_all_wstr(std::wstring str, const std::wstring& from, const std::wstring& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

std::wstring get_directory_w(const std::wstring& path) {
    size_t found = path.find_last_of(L"/\\");
    if (std::wstring::npos == found) return L"";
    return path.substr(0, found);
}

std::wstring get_filename_w(const std::wstring& path) {
    size_t found = path.find_last_of(L"/\\");
    if (std::wstring::npos == found) return path;
    return path.substr(found + 1);
}

std::wstring path_join_w(const std::wstring& p1, const std::wstring& p2_orig) {
    std::wstring p2 = p2_orig;
    if (p1.empty()) return p2;
    if (p2.empty()) return p1;

    // Normalize p2: remove leading slashes if p1 is not empty and not ending in slash
    if (p1.back() != L'/' && p1.back() != L'\\') {
        while (!p2.empty() && (p2.front() == L'/' || p2.front() == L'\\')) {
            p2.erase(0, 1);
        }
    }
     if (p2.empty() && (p1.back() == L'/' || p1.back() == L'\\')) return p1.substr(0, p1.length()-1); // if p2 became empty
     if (p2.empty()) return p1;


    wchar_t last_char_p1 = p1.back();
    wchar_t first_char_p2 = p2.front();

    if ((last_char_p1 == L'/' || last_char_p1 == L'\\') && (first_char_p2 == L'/' || first_char_p2 == L'\\')) {
        return p1 + p2.substr(1);
    }
    if ((last_char_p1 != L'/' && last_char_p1 != L'\\') && (first_char_p2 != L'/' && first_char_p2 != L'\\') && !p2.empty()) {
        return p1 + L"\\" + p2;
    }
    return p1 + p2;
}

void create_directories_recursive_w(const std::wstring& path) {
    if (path.empty()) return;
    // Check if directory exists
    DWORD attribs = GetFileAttributesW(path.c_str());
    if (attribs != INVALID_FILE_ATTRIBUTES && (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        return; // Already exists
    }

    // Create parent directories
    std::wstring parent_dir = get_directory_w(path);
    if (!parent_dir.empty() && parent_dir != path) { // Avoid infinite recursion for paths like "C:"
        create_directories_recursive_w(parent_dir);
    }

    // Create current directory
    if (!CreateDirectoryW(path.c_str(), NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) { // Could be a race condition
            throw std::runtime_error("Failed to create directory: " + wstring_to_utf8(path) + " Error: " + std::to_string(error));
        }
    }
}


std::wstring get_relative_path_w(const std::wstring& full_path, const std::wstring& base_path) {
    std::wstring norm_full_path = full_path;
    std::wstring norm_base_path = base_path;

    // Basic normalization: ensure base_path ends with a separator if not empty
    if (!norm_base_path.empty() && norm_base_path.back() != L'\\' && norm_base_path.back() != L'/') {
        norm_base_path += L'\\';
    }
    
    // Ensure full_path matches starting with base_path case-insensitively
    if (norm_full_path.length() >= norm_base_path.length() &&
        _wcsnicmp(norm_full_path.c_str(), norm_base_path.c_str(), norm_base_path.length()) == 0) {
        std::wstring rel_path = norm_full_path.substr(norm_base_path.length());
        // Remove leading separator if present (it's already handled by base_path ending with one)
        // This logic was slightly different in Go, path.Rel does more. This is simplified.
        // if (!rel_path.empty() && (rel_path[0] == L'\\' || rel_path[0] == L'/')) {
        //     return rel_path.substr(1);
        // }
        return rel_path;
    }
    return full_path; // Or throw error if not relative
}


// --- Binary I/O Helpers ---
void write_uint32_be(std::ostream& os, uint32_t val) {
    os.put(static_cast<char>((val >> 24) & 0xFF));
    os.put(static_cast<char>((val >> 16) & 0xFF));
    os.put(static_cast<char>((val >>  8) & 0xFF));
    os.put(static_cast<char>( val        & 0xFF));
    if (os.fail()) throw std::runtime_error("Failed to write uint32_be");
}

uint32_t read_uint32_be(std::istream& is) {
    uint32_t val = 0;
    char bytes[4];
    is.read(bytes, 4);
    if (is.gcount() != 4) throw std::runtime_error("Failed to read uint32_be: not enough bytes.");
    val |= (static_cast<uint32_t>(static_cast<unsigned char>(bytes[0])) << 24);
    val |= (static_cast<uint32_t>(static_cast<unsigned char>(bytes[1])) << 16);
    val |= (static_cast<uint32_t>(static_cast<unsigned char>(bytes[2])) <<  8);
    val |=  static_cast<uint32_t>(static_cast<unsigned char>(bytes[3]));
    return val;
}

void write_utf16_inv_len(std::ostream& os, const std::string& utf8_str) {
    if (utf8_str.empty()) {
        write_uint32_be(os, 0xFFFFFFFF); // ^0
        os.put(0); os.put(0); // Null terminator
        if (os.fail()) throw std::runtime_error("Failed to write empty utf16_inv_len string terminator");
        return;
    }

    std::wstring wide_str = utf8_to_wstring(utf8_str);
    uint32_t len_runes = static_cast<uint32_t>(wide_str.length());
    write_uint32_be(os, ~len_runes);

    for (wchar_t wc : wide_str) {
        // Replicate Go's behavior: take lower 16 bits of rune, write as UTF-16LE
        // wchar_t on Windows is UTF-16LE unit (uint16_t)
        os.put(static_cast<char>(wc & 0xFF));          // Low byte
        os.put(static_cast<char>((wc >> 8) & 0xFF));   // High byte
    }
    os.put(0); os.put(0); // Null terminator (2 bytes)
    if (os.fail()) throw std::runtime_error("Failed to write utf16_inv_len string data or terminator");
}

// For Key= (empty value), Go code writes inverted length as 0.
void write_utf16_inv_len_empty_val(std::ostream& os) {
    write_uint32_be(os, 0); // Special case from gow2/write.go for empty values
    // No string data, no null terminator needed as per gow2/write.go. ReadUtf16InvLen expects it if length is 0.
    // Let's check gowenc.ReadUtf16InvLen:
    // if length == 0 || length == 0xFFFFFFFF { return "", nil }
    // This means if inverted length is 0, it's an empty string, and no further bytes are read for it.
    // The Go code `gowenc.WriteUint32BE(w, 0)` in write.AppendIni is for the value string length directly.
}


std::string read_utf16_inv_len(std::istream& is) {
    uint32_t inverted_len_from_stream = read_uint32_be(is);

    if (inverted_len_from_stream == 0) {
        // Case for "Key=" type empty values where Go writer used WriteUint32BE(0).
        // No character data, no terminator bytes were written for this '0' length.
        return "";
    }

    uint32_t actual_char_count;
    if (inverted_len_from_stream == 0xFFFFFFFF) {
        actual_char_count = 0; // An empty string ""
    } else {
        actual_char_count = ~inverted_len_from_stream; // A non-empty string
    }

    if (actual_char_count > (10 * 1024 * 1024) / 2) { // Max ~10MB string (5M chars)
        std::ostringstream err_msg;
        err_msg << "UTF-16 string length too large: " << actual_char_count
                << " characters (inverted_len_from_stream was 0x" << std::hex << inverted_len_from_stream << std::dec << "). Stream position: " << is.tellg();
        throw std::runtime_error(err_msg.str());
    }

    std::vector<uint16_t> utf16_chars_vec;
    if (actual_char_count > 0) {
        utf16_chars_vec.resize(actual_char_count);
        for (uint32_t i = 0; i < actual_char_count; ++i) {
            char char_bytes[2];
            is.read(char_bytes, 2);
            if (is.gcount() != 2) {
                std::ostringstream err_msg;
                err_msg << "Failed to read 2 bytes for UTF-16 character data. Expected 2, got " << is.gcount()
                        << ". Target string char count: " << actual_char_count << ", current char index: " << i
                        << ". Stream position: " << is.tellg();
                throw std::runtime_error(err_msg.str());
            }
            utf16_chars_vec[i] = static_cast<uint16_t>(static_cast<unsigned char>(char_bytes[0])) |
                                 (static_cast<uint16_t>(static_cast<unsigned char>(char_bytes[1])) << 8);
        }
    }

    // Read the 2 bytes where the null terminator is expected, to advance the stream.
    // The original Go gowenc.ReadUtf16InvLen reads these 2 bytes as part of its (length*2+2) read,
    // but does not explicitly validate their content if length > 0 or length was 0xFFFFFFFF.
    char term_bytes_placeholder[2];
    is.read(term_bytes_placeholder, 2);
    if (is.gcount() != 2) {
        std::ostringstream err_msg;
        err_msg << "Failed to read 2 bytes for the expected null terminator position. Got " << is.gcount()
                << " bytes. Preceding string actual_char_count: " << actual_char_count
                << ". Stream position: " << is.tellg();
        // This check is important because the Go code also expects to read these 2 bytes.
        throw std::runtime_error(err_msg.str());
    }

    // REMOVED: Strict check on term_bytes_placeholder content to align with Go's behavior.
    // if (term_bytes_placeholder[0] != 0 || term_bytes_placeholder[1] != 0) {
    //     ... throw error ...
    // }

    if (actual_char_count == 0) {
        return ""; // Empty string, terminator position bytes were successfully consumed.
    }

    std::wstring wide_str(reinterpret_cast<const wchar_t*>(utf16_chars_vec.data()), actual_char_count);
    return wstring_to_utf8(wide_str);
}


// --- MD5 Implementation (RFC 1321) ---
namespace MD5 {
    // Constants for MD5Transform routine.
    #define S11 7
    #define S12 12
    #define S13 17
    #define S14 22
    #define S21 5
    #define S22 9
    #define S23 14
    #define S24 20
    #define S31 4
    #define S32 11
    #define S33 16
    #define S34 23
    #define S41 6
    #define S42 10
    #define S43 15
    #define S44 21

    typedef struct {
        uint32_t state[4];    /* state (ABCD) */
        uint32_t count[2];    /* number of bits, modulo 2^64 (lsb first) */
        unsigned char buffer[64]; /* input buffer */
    } MD5_CTX;

    void MD5Init(MD5_CTX*);
    void MD5Update(MD5_CTX*, const unsigned char*, unsigned int);
    void MD5Final(unsigned char[16], MD5_CTX*);
    static void MD5Transform(uint32_t[4], const unsigned char[64]);
    static void Encode(unsigned char*, const uint32_t*, unsigned int);
    static void Decode(uint32_t*, const unsigned char*, unsigned int);

    static unsigned char PADDING[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    /* F, G, H and I are basic MD5 functions. */
    #define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
    #define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
    #define H(x, y, z) ((x) ^ (y) ^ (z))
    #define I(x, y, z) ((y) ^ ((x) | (~z)))

    /* ROTATE_LEFT rotates x left n bits. */
    #define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

    /* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
    Rotation is separate from addition to prevent recomputation. */
    #define FF(a, b, c, d, x, s, ac) { \
        (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }
    #define GG(a, b, c, d, x, s, ac) { \
        (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }
    #define HH(a, b, c, d, x, s, ac) { \
        (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }
    #define II(a, b, c, d, x, s, ac) { \
        (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT ((a), (s)); \
        (a) += (b); \
    }

    void MD5Init(MD5_CTX* context) {
        context->count[0] = context->count[1] = 0;
        context->state[0] = 0x67452301;
        context->state[1] = 0xefcdab89;
        context->state[2] = 0x98badcfe;
        context->state[3] = 0x10325476;
    }

    void MD5Update(MD5_CTX* context, const unsigned char* input, unsigned int inputLen) {
        unsigned int i, index, partLen;
        index = (unsigned int)((context->count[0] >> 3) & 0x3F);
        if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
            context->count[1]++;
        context->count[1] += ((uint32_t)inputLen >> 29);
        partLen = 64 - index;
        if (inputLen >= partLen) {
            memcpy(&context->buffer[index], input, partLen);
            MD5Transform(context->state, context->buffer);
            for (i = partLen; i + 63 < inputLen; i += 64)
                MD5Transform(context->state, &input[i]);
            index = 0;
        }
        else i = 0;
        memcpy(&context->buffer[index], &input[i], inputLen - i);
    }

    void MD5Final(unsigned char digest[16], MD5_CTX* context) {
        unsigned char bits[8];
        unsigned int index, padLen;
        Encode(bits, context->count, 8);
        index = (unsigned int)((context->count[0] >> 3) & 0x3f);
        padLen = (index < 56) ? (56 - index) : (120 - index);
        MD5Update(context, PADDING, padLen);
        MD5Update(context, bits, 8);
        Encode(digest, context->state, 16);
        memset(context, 0, sizeof(*context));
    }

    static void MD5Transform(uint32_t state[4], const unsigned char block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
        Decode(x, block, 64);
        FF(a, b, c, d, x[0], S11, 0xd76aa478); FF(d, a, b, c, x[1], S12, 0xe8c7b756);
        FF(c, d, a, b, x[2], S13, 0x242070db); FF(b, c, d, a, x[3], S14, 0xc1bdceee);
        FF(a, b, c, d, x[4], S11, 0xf57c0faf); FF(d, a, b, c, x[5], S12, 0x4787c62a);
        FF(c, d, a, b, x[6], S13, 0xa8304613); FF(b, c, d, a, x[7], S14, 0xfd469501);
        FF(a, b, c, d, x[8], S11, 0x698098d8); FF(d, a, b, c, x[9], S12, 0x8b44f7af);
        FF(c, d, a, b, x[10], S13, 0xffff5bb1); FF(b, c, d, a, x[11], S14, 0x895cd7be);
        FF(a, b, c, d, x[12], S11, 0x6b901122); FF(d, a, b, c, x[13], S12, 0xfd987193);
        FF(c, d, a, b, x[14], S13, 0xa679438e); FF(b, c, d, a, x[15], S14, 0x49b40821);
        GG(a, b, c, d, x[1], S21, 0xf61e2562); GG(d, a, b, c, x[6], S22, 0xc040b340);
        GG(c, d, a, b, x[11], S23, 0x265e5a51); GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
        GG(a, b, c, d, x[5], S21, 0xd62f105d); GG(d, a, b, c, x[10], S22, 0x02441453);
        GG(c, d, a, b, x[15], S23, 0xd8a1e681); GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
        GG(a, b, c, d, x[9], S21, 0x21e1cde6); GG(d, a, b, c, x[14], S22, 0xc33707d6);
        GG(c, d, a, b, x[3], S23, 0xf4d50d87); GG(b, c, d, a, x[8], S24, 0x455a14ed);
        GG(a, b, c, d, x[13], S21, 0xa9e3e905); GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
        GG(c, d, a, b, x[7], S23, 0x676f02d9); GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);
        HH(a, b, c, d, x[5], S31, 0xfffa3942); HH(d, a, b, c, x[8], S32, 0x8771f681);
        HH(c, d, a, b, x[11], S33, 0x6d9d6122); HH(b, c, d, a, x[14], S34, 0xfde5380c);
        HH(a, b, c, d, x[1], S31, 0xa4beea44); HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
        HH(c, d, a, b, x[7], S33, 0xf6bb4b60); HH(b, c, d, a, x[10], S34, 0xbebfbc70);
        HH(a, b, c, d, x[13], S31, 0x289b7ec6); HH(d, a, b, c, x[0], S32, 0xeaa127fa);
        HH(c, d, a, b, x[3], S33, 0xd4ef3085); HH(b, c, d, a, x[6], S34, 0x04881d05);
        HH(a, b, c, d, x[9], S31, 0xd9d4d039); HH(d, a, b, c, x[12], S32, 0xe6db99e5);
        HH(c, d, a, b, x[15], S33, 0x1fa27cf8); HH(b, c, d, a, x[2], S34, 0xc4ac5665);
        II(a, b, c, d, x[0], S41, 0xf4292244); II(d, a, b, c, x[7], S42, 0x432aff97);
        II(c, d, a, b, x[14], S43, 0xab9423a7); II(b, c, d, a, x[5], S44, 0xfc93a039);
        II(a, b, c, d, x[12], S41, 0x655b59c3); II(d, a, b, c, x[3], S42, 0x8f0ccc92);
        II(c, d, a, b, x[10], S43, 0xffeff47d); II(b, c, d, a, x[1], S44, 0x85845dd1);
        II(a, b, c, d, x[8], S41, 0x6fa87e4f); II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
        II(c, d, a, b, x[6], S43, 0xa3014314); II(b, c, d, a, x[13], S44, 0x4e0811a1);
        II(a, b, c, d, x[4], S41, 0xf7537e82); II(d, a, b, c, x[11], S42, 0xbd3af235);
        II(c, d, a, b, x[2], S43, 0x2ad7d2bb); II(b, c, d, a, x[9], S44, 0xeb86d391);
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        memset(x, 0, sizeof(x));
    }

    static void Encode(unsigned char* output, const uint32_t* input, unsigned int len) {
        for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
            output[j] = (unsigned char)(input[i] & 0xff);
            output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
            output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
            output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
        }
    }

    static void Decode(uint32_t* output, const unsigned char* input, unsigned int len) {
        for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
            output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
            (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
    }

    std::string CalculateMD5(const std::vector<char>& data) {
        MD5_CTX context;
        unsigned char digest[16];
        MD5Init(&context);
        MD5Update(&context, reinterpret_cast<const unsigned char*>(data.data()), static_cast<unsigned int>(data.size()));
        MD5Final(digest, &context);
        
        std::stringstream ss;
        for(int i = 0; i < 16; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        return ss.str();
    }
}


// --- INI Parsing and Data Structures ---
struct IniKeyValue {
    std::string key;
    std::string value; // For reading, this is the raw value. For writing, it can be one of multiple.
};

struct IniSection {
    std::string name;
    std::vector<IniKeyValue> values; // Direct key-value pairs as read.
    // For handling shadows (multiple values for one key) more robustly during pack:
    std::map<std::string, std::vector<std::string>> shadowed_values;
};

struct IniFile {
    std::string name_on_disk; // Original file path
    std::string coalesced_name; // Name as it appears in the binary
    std::vector<IniSection> sections;
};

// Basic INI Parser
// Does not handle comments within values, complex escapes, or continuations.
// Supports [Section] and Key=Value. Multiple Key=Value lines for the same key create shadows.
IniFile parse_ini_file(const std::wstring& filePath) {
    IniFile iniFile;
    iniFile.name_on_disk = wstring_to_utf8(filePath);

    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open INI file: " + iniFile.name_on_disk);
    }

    std::string line;
    IniSection* currentSection = nullptr;
    int lineNum = 0;

    while (std::getline(file, line)) {
        lineNum++;
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty() || line[0] == ';' || line[0] == '#') { // Skip empty lines and comments
            continue;
        }

        if (line[0] == '[' && line.back() == ']') { // Section
            std::string sectionName = line.substr(1, line.length() - 2);
            iniFile.sections.emplace_back();
            currentSection = &iniFile.sections.back();
            currentSection->name = sectionName;
        } else if (currentSection) { // Key-Value
            size_t equalsPos = line.find('=');
            if (equalsPos != std::string::npos) {
                std::string key = line.substr(0, equalsPos);
                std::string value = line.substr(equalsPos + 1);
                // Trim key/value
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                // Store directly for simplicity; shadowing handled during pack write.
                // currentSection->values.push_back({key, value});
                currentSection->shadowed_values[key].push_back(value);
            } else {
                 // Key without value e.g. "MyKey"
                 std::string key = line;
                 key.erase(0, key.find_first_not_of(" \t"));
                 key.erase(key.find_last_not_of(" \t") + 1);
                 currentSection->shadowed_values[key].push_back(""); // Empty value
            }
        }
    }
    return iniFile;
}

void write_ini_file_to_disk(const IniFile& iniData, const std::wstring& baseDir, const std::string& prefix_from_metadata) {
    // file.Name in Go is coalesced name. realFileName is without prefix.
    std::string realFileName = iniData.coalesced_name;
    if (!prefix_from_metadata.empty() && realFileName.rfind(prefix_from_metadata, 0) == 0) {
        realFileName = realFileName.substr(prefix_from_metadata.length());
    }
    realFileName = replace_all_str(realFileName, "\\", "/"); // Normalize to forward slashes for processing

    std::wstring wRealFileName = utf8_to_wstring(realFileName);
    std::wstring fullOutputPath = path_join_w(baseDir, wRealFileName);
    
    std::wstring dirPart = get_directory_w(fullOutputPath);
    create_directories_recursive_w(dirPart);

    std::ofstream outFile(fullOutputPath);
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to create output INI file: " + wstring_to_utf8(fullOutputPath));
    }

    for (const auto& binarySection : iniData.sections) {
        if (!binarySection.name.empty() && binarySection.name != "DEFAULT") { // gopkg.in/ini.v1 convention
             outFile << "[" << binarySection.name << "]\n";
        }
        // The IniFile struct from parsing stores values in shadowed_values.
        // The BinaryIniFile struct that read_coalesced_ini_files produces has a flat list of key/value.
        // The structure `IniFile` here should match `BinaryIniFile` from Go `read.go` when used for `write_ini_file_to_disk`.
        // So it should have `std::vector<IniKeyValue> values;` per section.
        // Let's assume `IniFile` struct for unpacking will directly have `IniKeyValue` list.
        for (const auto& kv : binarySection.values) { // This implies binarySection.values is populated for unpacking
            std::string key_to_write = kv.key;
            // The Go code `readIniValue` transforms keys starting with ; or # to IGNORED_SC_ / IGNORED_SH_
            // This should be reversed if we were writing it, but gopkg.in/ini does it automatically.
            // Our simple writer does not. The read.go code stores them modified. So write them as is.
            
            std::string value_to_write = kv.value;
            // The `\\\\` to `` `\\\\` `` transformation in Go's `readIniValue`
            // is applied when reading from binary to BinaryIniKeyValue. So `kv.value` already has it.
            outFile << key_to_write << "=" << value_to_write << "\n";
        }
        outFile << "\n"; // Blank line between sections
    }
}


// --- Coalesced INI Structures (mirroring Go) ---
struct BinaryIniKeyValue { // Used by read.go
    std::string Key;
    std::string Value;
};

struct BinaryIniSection { // Used by read.go
    std::string Name;
    std::vector<BinaryIniKeyValue> Values;
};

struct BinaryIniFile { // Used by read.go. This is what `IniFile` should be for unpacking
    std::string Name; // This is the coalesced_name
    std::vector<BinaryIniSection> Sections;
};

struct BinaryCoalescedIniFiles { // Used by read.go
    uint32_t fileCount;
    std::vector<BinaryIniFile> Files;
};

struct Metadata {
    std::string Prefix;
};

// --- Core Unpack Logic ---
std::string detect_prefix(std::istream& reader_stream_for_detect) {
    // This function needs to read the coalesced file without fully parsing everything,
    // just enough to get file names. Or, parse fully and then detect.
    // The Go code re-reads. For simplicity, let's assume full parse then detect.
    // This means the reader_stream_for_detect will be consumed.
    // A better way is to pass a copy of the buffer or re-open the file.
    // Or, make read_coalesced_ini_files return the raw names too.
    // For this example, we'll pass the already parsed structure.

    // This function now takes the parsed files
    auto& coalesced_files_data = *reinterpret_cast<BinaryCoalescedIniFiles*>(nullptr); // Placeholder for actual data
    // The actual implementation will be part of Unpack where BinaryCoalescedIniFiles is available.
    return ""; // Placeholder
}


BinaryCoalescedIniFiles read_coalesced_ini_files(std::istream& r) {
    BinaryCoalescedIniFiles result;
    result.fileCount = read_uint32_be(r);

    // --- DEBUG OUTPUT START ---
    {
        std::wstringstream wss;
        wss << L"DEBUG: Initial fileCount read = " << result.fileCount
            << L" (0x" << std::hex << result.fileCount << std::dec << L")"
            << L". Stream position after read: " << r.tellg();
        MessageBoxW(NULL, wss.str().c_str(), L"Debug: fileCount", MB_OK);
    }
    // --- DEBUG OUTPUT END ---

    if (result.fileCount > 50000) { // Your increased limit
        throw std::runtime_error("Too many files in coalesced data: " + std::to_string(result.fileCount));
    }
    result.Files.resize(result.fileCount);

    for (uint32_t i = 0; i < result.fileCount; ++i) {
    BinaryIniFile& currentFile = result.Files[i];

    if (i == 0) {
        // Potentially problematic first file.
        // Let's see what its inverted length is.
        std::streampos pos_before_name_len = r.tellg();
        uint32_t first_filename_inverted_len = read_uint32_be(r);
        r.seekg(pos_before_name_len); // Rewind

        if (first_filename_inverted_len == 0xFFFF0001) {
            // This is our problematic length.
            // What if we just "pretend" it was a short, empty name to skip the massive read?
            // This is a HACK for testing if the *rest* of the file is okay.
            MessageBoxW(NULL, L"HACK: Detected problematic inverted len for first file. Attempting to read it as an empty string to see if subsequent data is valid.", L"Hack Active", MB_OK);
            currentFile.Name = ""; // Assign empty name
            // We need to consume the inverted_len (4 bytes) and its (non-existent) terminator (2 bytes)
            // that read_utf16_inv_len would have if it read an empty string with 0xFFFFFFFF.
            read_uint32_be(r); // Consume the 0xFFFF0001
            char dummy_term[2];
            r.read(dummy_term, 2); // Consume 2 more bytes (where its "terminator" would be)
                                   // The original read_utf16_inv_len for actual_char_count=0 (from 0xFFFFFFFF)
                                   // does read a terminator.
                                   // However, our current read_utf16_inv_len for 0xFFFF0001 (65534 chars)
                                   // also reads 2 bytes for terminator. So we just need to consume 4+2 = 6 bytes past current r.tellg()
                                   // if we entirely bypass read_utf16_inv_len for this case.
                                   // Simpler: let read_utf16_inv_len read it, and if the name matches the long one, clear it.
                                   // But we know it will throw on sectionCount.
                                   //
                                   // Let's just consume the 0xFFFF0001 from the stream and the 2 bytes that were its "terminator" (A3 37)
                                   // read_uint32_be(r); // Consume 0xFFFF0001
                                   // char junk[2]; r.read(junk,2); // Consume A3 37 (the bogus terminator)
                                   // currentFile.Name = L"<SKIPPED_FIRST_FILE_DUE_TO_BAD_LENGTH>";
                                   // The read_utf16_inv_len call below will be skipped in this (i==0 && specific_len) branch.
        } else {
             currentFile.Name = read_utf16_inv_len(r);
        }
    } else { // For i > 0
        currentFile.Name = read_utf16_inv_len(r);
    }

 // --- DEBUG OUTPUT START for filename's inverted length ---
    if (i == 0) { // Only for the first file, which seems to be the problem child
        std::streampos pos_before_name_len = r.tellg();
        uint32_t first_filename_inverted_len = read_uint32_be(r); // Temporarily read it
        r.seekg(pos_before_name_len); // IMPORTANT: Rewind so read_utf16_inv_len reads it again

        std::wstringstream wss;
        wss << L"DEBUG: For first file (i=0), inverted_len for Name is about to be read. "
            << L"Value peeked: 0x" << std::hex << first_filename_inverted_len << std::dec
            << L" (~" << (~first_filename_inverted_len) << L" chars)."
            << L" Stream position: " << pos_before_name_len;
        MessageBoxW(NULL, wss.str().c_str(), L"Debug: First Filename Inverted Len", MB_OK);
    }
    // --- DEBUG OUTPUT END ---












        currentFile.Name = read_utf16_inv_len(r);

// --- DEBUG OUTPUT START for section count ---
    if (i == 0) { // Only for the first file
        std::streampos pos_before_section_count = r.tellg();
        uint32_t first_section_count_peek = read_uint32_be(r); // Temporarily read
        r.seekg(pos_before_section_count); // IMPORTANT: Rewind

        std::wstringstream wss;
        wss << L"DEBUG: For first file (i=0), Name read as: '" << utf8_to_wstring(currentFile.Name.substr(0, 50)) << L"...'"
            << L"\nsectionCount is about to be read. Value peeked: " << first_section_count_peek
            << L" (0x" << std::hex << first_section_count_peek << std::dec << L")."
            << L" Stream position: " << pos_before_section_count;
        MessageBoxW(NULL, wss.str().c_str(), L"Debug: First File Section Count", MB_OK);
    }
    // --- DEBUG OUTPUT END ---




        uint32_t sectionCount = read_uint32_be(r);
         if (sectionCount > 30000) { // Sanity check
            throw std::runtime_error("Too many sections in file " + currentFile.Name + ": " + std::to_string(sectionCount));
        }
        currentFile.Sections.resize(sectionCount);

        for (uint32_t j = 0; j < sectionCount; ++j) {
            BinaryIniSection& currentSection = currentFile.Sections[j];
            currentSection.Name = read_utf16_inv_len(r);

            uint32_t valueCount = read_uint32_be(r);
            if (valueCount > 300000) { // Sanity check
                 throw std::runtime_error("Too many values in section " + currentSection.Name + ": " + std::to_string(valueCount));
            }
            currentSection.Values.resize(valueCount);

            for (uint32_t k = 0; k < valueCount; ++k) {
                BinaryIniKeyValue& currentKV = currentSection.Values[k];
                currentKV.Key = read_utf16_inv_len(r);
                // Apply transformations from Go's readIniValue
                if (currentKV.Key.rfind(";", 0) == 0) { // Starts with ;
                    currentKV.Key = "IGNORED_SC_" + currentKV.Key.substr(1);
                } else if (currentKV.Key.rfind("#", 0) == 0) { // Starts with #
                    currentKV.Key = "IGNORED_SH_" + currentKV.Key.substr(1);
                }

                currentKV.Value = read_utf16_inv_len(r);
                if (currentKV.Value == "\\\\\\\\") { // Four backslashes
                    currentKV.Value = "`" + currentKV.Value + "`";
                }
            }
        }
    }
    return result;
}

std::string actual_detect_prefix(const BinaryCoalescedIniFiles& coalesced) {
    if (coalesced.Files.empty()) {
        return ""; // No files, no prefix
    }
    std::map<std::string, bool> prefixMap;
    for (const auto& file : coalesced.Files) {
        size_t splitAt = std::string::npos;
        for (size_t i = 0; i < file.Name.length(); ++i) {
            if (file.Name[i] != '\\' && file.Name[i] != '.') {
                splitAt = i;
                break;
            }
        }
        if (splitAt != std::string::npos && splitAt > 0) { // Ensure prefix is not empty
             prefixMap[file.Name.substr(0, splitAt)] = true;
        } else if (splitAt == 0) { // Prefix is empty string if name starts with non-prefix char
            prefixMap[""] = true;
        } else { // Name consists only of \ and . or is empty
            // This case needs clarification from Go's behavior.
            // Let's assume it means no valid prefix part found, or use full name?
            // Go code: prefixMap[file.Name[:splitAt]]
            // If splitAt is -1 (not found), Go slices file.Name[:-1] which is almost all of it. This is likely not intended.
            // If splitAt remains -1 (original Go code default was -1, then set to i),
            // and loop doesn't find char, file.Name[:splitAt] is file.Name[:0] effectively if splitAt becomes 0.
            // If file.Name = "...", splitAt becomes 3. file.Name[:3] is "..."
            // If file.Name = "..\\foo", splitAt becomes 3. file.Name[:3] is "..\\"
            // This logic needs careful check. The Go code is: file.Name[:splitAt]. If splitAt is where the first non-'\' or non-'.' char is, then it's correct.
            // If no such char, splitAt remains its initial value. In Go, slice[:neg] is invalid. Slice[:len(str)] is fine.
            // Corrected logic based on Go:
            // splitAt = -1 -> file.Name[:splitAt] means file.Name up to splitAt characters.
            // if splitAt is not found, original Go code file.Name[:splitAt] where splitAt is initial -1 will cause error.
            // It must find a char or behavior is undefined.
            // The C++ version above `splitAt > 0` handles prefix part. If `splitAt == 0`, prefix is empty.
            // If `splitAt == std::string::npos` means only `.` and `\` or empty.
            // E.g. `..\..\Default.ini` -> prefix `..\..\`
            // The loop in Go assigns `splitAt = i` then `break`. So `splitAt` is the index of the first non-special char.
            // `file.Name[:splitAt]` is the prefix *before* that character.
            if (splitAt != std::string::npos) { // splitAt is the index of the first "real" char
                 prefixMap[file.Name.substr(0, splitAt)] = true;
            } else { // Name is all `.` and `\` or empty. This implies the whole name is prefix-like.
                 prefixMap[file.Name] = true;
            }
        }
    }

    if (prefixMap.size() > 1) {
        std::string allPrefixes;
        for(const auto& pair : prefixMap) allPrefixes += "'" + pair.first + "' ";
        throw std::runtime_error("More than one prefix found: " + allPrefixes);
    }
    if (prefixMap.empty()) { // Should not happen if there are files, unless all names are empty or logic error
        return ""; // Or throw error
    }
    return prefixMap.begin()->first;
}


void UnpackCoalesced(const std::wstring& inputFile, const std::wstring& outputDir, HWND progress_hwnd = NULL) {
    std::ifstream inFileStream(inputFile, std::ios::binary);
    if (!inFileStream.is_open()) {
        throw std::runtime_error("Failed to open input file: " + wstring_to_utf8(inputFile));
    }
    
    // Read entire file into buffer for MD5 and potentially for re-reading for prefix detection
    // though our read_coalesced_ini_files is destructive on the stream.
    // For simplicity, we'll parse, then detect prefix from parsed data.
    BinaryCoalescedIniFiles coalesced_data = read_coalesced_ini_files(inFileStream);
    inFileStream.close(); // Done with the file

    std::string detected_prefix = actual_detect_prefix(coalesced_data);

    // Write metadata.json
    Metadata meta;
    meta.Prefix = detected_prefix;
    std::wstring metadataPath = path_join_w(outputDir, L"metadata.json");
    create_directories_recursive_w(get_directory_w(metadataPath)); // Ensure outputDir exists
    std::ofstream metaFile(metadataPath);
    if (!metaFile.is_open()) {
        throw std::runtime_error("Failed to create metadata.json");
    }
    // Simple JSON generation
    metaFile << "{\n";
    metaFile << "  \"prefix\": \"" << replace_all_str(meta.Prefix, "\\", "\\\\") << "\"\n"; // Escape backslashes in JSON
    metaFile << "}\n";
    metaFile.close();

    for (const auto& file_to_unpack : coalesced_data.Files) {
        // The IniFile struct for write_ini_file_to_disk needs to match BinaryIniFile structure
        ::IniFile disk_ini_representation; // Using :: to distinguish from local IniFile type if any
        disk_ini_representation.coalesced_name = file_to_unpack.Name;
        for(const auto& bin_sec : file_to_unpack.Sections) { // bin_sec is const BinaryIniSection&
            ::IniSection disk_sec_representation;
            disk_sec_representation.name = bin_sec.Name; // string to string is fine

            // Correctly populate disk_sec_representation.values from bin_sec.Values
            disk_sec_representation.values.clear();
            disk_sec_representation.values.reserve(bin_sec.Values.size());

            for (const auto& binary_kv : bin_sec.Values) { // binary_kv is const BinaryIniKeyValue&
                ::IniKeyValue disk_kv;
                disk_kv.key = binary_kv.Key;     // Map 'Key' (from BinaryIniKeyValue) to 'key' (for IniKeyValue)
                disk_kv.value = binary_kv.Value; // Map 'Value' to 'value'
                disk_sec_representation.values.push_back(disk_kv);
            }
            // End of correction for populating values

            disk_ini_representation.sections.push_back(disk_sec_representation);
        }
        write_ini_file_to_disk(disk_ini_representation, outputDir, detected_prefix);
        // Update progress if progress_hwnd is valid
    }
}


// --- Core Pack Logic ---
void recursive_file_list_w(const std::wstring& currentDir, std::vector<std::wstring>& files, const std::wstring& baseDir) {
    WIN32_FIND_DATAW findFileData;
    std::wstring searchPath = path_join_w(currentDir, L"*");
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return; 
    }

    do {
        if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring fullPath = path_join_w(currentDir, findFileData.cFileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            recursive_file_list_w(fullPath, files, baseDir);
        } else {
            std::wstring lowerName = findFileData.cFileName;
            for (wchar_t& c : lowerName) c = towlower(c); // Convert to lowercase
            if (lowerName.length() >= 4 && (lowerName.substr(lowerName.length() - 4) == L".ini" || lowerName.substr(lowerName.length() - 4) == L".int")) {
                files.push_back(fullPath);
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) {
        // Could throw here if specific error handling is needed
    }
}

std::vector<char> PackCoalesced(const std::vector<std::wstring>& inputFilesPaths, // list of full paths to INI files
                               const std::wstring& baseDir,      // Base directory to make paths relative to
                               const std::string& prefix_str,   // The prefix string e.g. "..\\"
                               HWND progress_hwnd = NULL) {
    std::ostringstream out_buffer(std::ios::binary);

    write_uint32_be(out_buffer, static_cast<uint32_t>(inputFilesPaths.size()));

    for (const auto& wFilePath : inputFilesPaths) {
        IniFile parsed_ini = parse_ini_file(wFilePath); // IniFile from parsing on disk
        
        std::wstring relPath_w = get_relative_path_w(wFilePath, baseDir);
        std::string relPath_utf8 = wstring_to_utf8(relPath_w);
        std::string coalescedName = prefix_str + replace_all_str(relPath_utf8, "/", "\\"); // Ensure backslashes

        write_utf16_inv_len(out_buffer, coalescedName);

        // Count sections excluding "DEFAULT" (though our parser doesn't create it explicitly)
        uint32_t actualSectionCount = 0;
        for (const auto& sec : parsed_ini.sections) {
            if (sec.name != "DEFAULT") { // Standard INI libs might produce a DEFAULT section
                actualSectionCount++;
            }
        }
        write_uint32_be(out_buffer, actualSectionCount);

        for (const auto& section : parsed_ini.sections) {
            if (section.name == "DEFAULT") continue;

            write_utf16_inv_len(out_buffer, section.name);
            
            // Count total key-value pairs including shadows
            uint32_t totalKeyValuePairs = 0;
            for (const auto& pair : section.shadowed_values) {
                totalKeyValuePairs += static_cast<uint32_t>(pair.second.size());
                 if (pair.second.empty()) { // Handle Key= case (empty value list means one entry with empty value)
                    totalKeyValuePairs++;
                }
            }
            write_uint32_be(out_buffer, totalKeyValuePairs);

            for (auto const& [key_str, values_vec] : section.shadowed_values) {
                std::string keyName = key_str;
                // Reverse the IGNORED_SC_ / IGNORED_SH_ transformation for writing to binary
                if (keyName.rfind("IGNORED_SC_", 0) == 0) {
                    keyName = ";" + keyName.substr(sizeof("IGNORED_SC_") -1);
                } else if (keyName.rfind("IGNORED_SH_", 0) == 0) {
                    keyName = "#" + keyName.substr(sizeof("IGNORED_SH_") -1);
                }

                if (values_vec.empty()){ // Case: Key= (empty value)
                    write_utf16_inv_len(out_buffer, keyName);
                    write_utf16_inv_len_empty_val(out_buffer); // Write inverted length 0 for value
                } else {
                    for (const auto& val_str : values_vec) {
                        write_utf16_inv_len(out_buffer, keyName);
                        write_utf16_inv_len(out_buffer, val_str);
                    }
                }
            }
        }
        // Update progress if progress_hwnd is valid
    }

    std::string s = out_buffer.str();
    return std::vector<char>(s.begin(), s.end());
}


// --- Win32 GUI ---
HINSTANCE hInst;
HWND hInputFileUnpack, hOutputDirUnpack, hBtnUnpack;
HWND hInputDirPack, hOutputFilePack, hPrefixPack, hBtnPack;
HWND hStatusText; // For displaying messages

#define IDC_INPUT_FILE_UNPACK 101
#define IDC_OUTPUT_DIR_UNPACK 102
#define IDC_BTN_BROWSE_INPUT_UNPACK 103
#define IDC_BTN_BROWSE_OUTPUT_UNPACK 104
#define IDC_BTN_UNPACK 105

#define IDC_INPUT_DIR_PACK 201
#define IDC_OUTPUT_FILE_PACK 202
#define IDC_PREFIX_PACK 203
#define IDC_BTN_BROWSE_INPUT_PACK 204
#define IDC_BTN_BROWSE_OUTPUT_PACK 205
#define IDC_BTN_PACK 206

#define IDC_STATUS_TEXT 301

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;
    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = L"CoalescedIniToolWindowClass";
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION); 
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);


    if (!RegisterClassExW(&wcex)) {
        MessageBoxW(NULL, L"Window Registration Failed!", L"Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    HWND hwnd = CreateWindowExW(
        0, L"CoalescedIniToolWindowClass", L"Coalesced INI Tool C++",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        600, 450, nullptr, nullptr, hInstance, nullptr);

    if (!hwnd) {
        MessageBoxW(NULL, L"Window Creation Failed!", L"Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        CreateControls(hwnd);
        break;
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case IDC_BTN_BROWSE_INPUT_UNPACK:
            SetWindowTextW(hInputFileUnpack, ShowOpenFileDialog(hwnd, L"Coalesced Binary Files (*.bin)\0*.bin\0All Files (*.*)\0*.*\0", L"Select Coalesced INI File").c_str());
            break;
        case IDC_BTN_BROWSE_OUTPUT_UNPACK:
            SetWindowTextW(hOutputDirUnpack, ShowBrowseFolderDialog(hwnd, L"Select Output Directory for INI Files").c_str());
            break;
        case IDC_BTN_UNPACK:
            HandleUnpack(hwnd);
            break;
        case IDC_BTN_BROWSE_INPUT_PACK:
            SetWindowTextW(hInputDirPack, ShowBrowseFolderDialog(hwnd, L"Select Input Directory with INI Files").c_str());
            break;
        case IDC_BTN_BROWSE_OUTPUT_PACK:
            SetWindowTextW(hOutputFilePack, ShowSaveFileDialog(hwnd, L"Coalesced Binary Files (*.bin)\0*.bin\0All Files (*.*)\0*.*\0", L"Save Coalesced INI File As", L"Coalesced_int.bin").c_str());
            break;
        case IDC_BTN_PACK:
            HandlePack(hwnd);
            break;
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
        }
    }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

void CreateControls(HWND hwnd) {
    // --- Unpack Group ---
    CreateWindowW(L"STATIC", L"Unpack Coalesced INI File:", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 10, 200, 20, hwnd, NULL, hInst, NULL);
    CreateWindowW(L"STATIC", L"Input File (.bin):", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 40, 120, 20, hwnd, NULL, hInst, NULL);
    hInputFileUnpack = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 140, 40, 300, 20, hwnd, (HMENU)IDC_INPUT_FILE_UNPACK, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse...", WS_VISIBLE | WS_CHILD, 450, 40, 80, 20, hwnd, (HMENU)IDC_BTN_BROWSE_INPUT_UNPACK, hInst, NULL);

    CreateWindowW(L"STATIC", L"Output Directory:", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 70, 120, 20, hwnd, NULL, hInst, NULL);
    hOutputDirUnpack = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 140, 70, 300, 20, hwnd, (HMENU)IDC_OUTPUT_DIR_UNPACK, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse...", WS_VISIBLE | WS_CHILD, 450, 70, 80, 20, hwnd, (HMENU)IDC_BTN_BROWSE_OUTPUT_UNPACK, hInst, NULL);
    
    hBtnUnpack = CreateWindowW(L"BUTTON", L"Unpack", WS_VISIBLE | WS_CHILD, 250, 100, 100, 30, hwnd, (HMENU)IDC_BTN_UNPACK, hInst, NULL);

    // --- Pack Group ---
    CreateWindowW(L"STATIC", L"Pack INI Files to Coalesced:", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 150, 200, 20, hwnd, NULL, hInst, NULL);
    CreateWindowW(L"STATIC", L"Input Directory (INIs):", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 180, 150, 20, hwnd, NULL, hInst, NULL);
    hInputDirPack = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 170, 180, 270, 20, hwnd, (HMENU)IDC_INPUT_DIR_PACK, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse...", WS_VISIBLE | WS_CHILD, 450, 180, 80, 20, hwnd, (HMENU)IDC_BTN_BROWSE_INPUT_PACK, hInst, NULL);

    CreateWindowW(L"STATIC", L"Output File (.bin):", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 210, 150, 20, hwnd, NULL, hInst, NULL);
    hOutputFilePack = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 170, 210, 270, 20, hwnd, (HMENU)IDC_OUTPUT_FILE_PACK, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Browse...", WS_VISIBLE | WS_CHILD, 450, 210, 80, 20, hwnd, (HMENU)IDC_BTN_BROWSE_OUTPUT_PACK, hInst, NULL);

    CreateWindowW(L"STATIC", L"Prefix (e.g., ..\\\\):", WS_VISIBLE | WS_CHILD | SS_LEFT, 10, 240, 150, 20, hwnd, NULL, hInst, NULL);
    hPrefixPack = CreateWindowW(L"EDIT", L"..\\", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 170, 240, 270, 20, hwnd, (HMENU)IDC_PREFIX_PACK, hInst, NULL);
    
    hBtnPack = CreateWindowW(L"BUTTON", L"Pack", WS_VISIBLE | WS_CHILD, 250, 270, 100, 30, hwnd, (HMENU)IDC_BTN_PACK, hInst, NULL);

    // Status text
    hStatusText = CreateWindowW(L"STATIC", L"Ready.", WS_VISIBLE | WS_CHILD | SS_LEFT | WS_BORDER, 10, 320, 560, 60, hwnd, (HMENU)IDC_STATUS_TEXT, hInst, NULL);
}

void SetStatus(const std::wstring& status) {
    SetWindowTextW(hStatusText, status.c_str());
}


void HandleUnpack(HWND hwnd) {
    wchar_t inputFile[MAX_PATH], outputDir[MAX_PATH];
    GetWindowTextW(hInputFileUnpack, inputFile, MAX_PATH);
    GetWindowTextW(hOutputDirUnpack, outputDir, MAX_PATH);

    if (wcslen(inputFile) == 0 || wcslen(outputDir) == 0) {
        MessageBoxW(hwnd, L"Please select input file and output directory.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    SetStatus(L"Unpacking... Please wait.");
    try {
        UnpackCoalesced(inputFile, outputDir, NULL /* progress hwnd */);
        std::wstring successMsg = L"Unpacked successfully to: " + std::wstring(outputDir);
        MessageBoxW(hwnd, successMsg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
        SetStatus(L"Unpack complete.");
    } catch (const std::exception& e) {
        std::string error_str = "Unpack failed: ";
        error_str += e.what();
        MessageBoxA(hwnd, error_str.c_str(), "Error", MB_OK | MB_ICONERROR);
        SetStatus(L"Unpack failed.");
    }
}

void HandlePack(HWND hwnd) {
    wchar_t inputDir[MAX_PATH], outputFile[MAX_PATH], prefix_w[MAX_PATH];
    GetWindowTextW(hInputDirPack, inputDir, MAX_PATH);
    GetWindowTextW(hOutputFilePack, outputFile, MAX_PATH);
    GetWindowTextW(hPrefixPack, prefix_w, MAX_PATH);
    
    std::string prefix_utf8 = wstring_to_utf8(prefix_w);

    if (wcslen(inputDir) == 0 || wcslen(outputFile) == 0) {
        MessageBoxW(hwnd, L"Please select input directory, output file, and specify prefix.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    SetStatus(L"Packing... Please wait.");
    try {
        std::vector<std::wstring> fileList;
        recursive_file_list_w(inputDir, fileList, inputDir);
        
        if (fileList.empty()) {
            MessageBoxW(hwnd, L"No .ini or .int files found in the input directory.", L"Warning", MB_OK | MB_ICONWARNING);
            SetStatus(L"Packing complete (no files found).");
            return;
        }

        std::vector<char> packed_data = PackCoalesced(fileList, inputDir, prefix_utf8, NULL);
        
        std::ofstream outFileStream(outputFile, std::ios::binary | std::ios::trunc);
        if (!outFileStream.is_open()) {
            throw std::runtime_error("Failed to create output file: " + wstring_to_utf8(outputFile));
        }
        outFileStream.write(packed_data.data(), packed_data.size());
        outFileStream.close();

        std::string md5_hash = MD5::CalculateMD5(packed_data);
        
        std::wstringstream successMsg;
        successMsg << L"Packed " << fileList.size() << L" files successfully to: " << outputFile << L"\n";
        successMsg << L"File length: " << packed_data.size() << L" bytes\n";
        successMsg << L"File hash (MD5): " << utf8_to_wstring(md5_hash).c_str();

        MessageBoxW(hwnd, successMsg.str().c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
        SetStatus(L"Pack complete.");

    } catch (const std::exception& e) {
        std::string error_str = "Pack failed: ";
        error_str += e.what();
        MessageBoxA(hwnd, error_str.c_str(), "Error", MB_OK | MB_ICONERROR);
        SetStatus(L"Pack failed.");
    }
}


// --- File/Folder Dialog Helpers ---
std::wstring ShowOpenFileDialog(HWND hwnd, const wchar_t* filter, const wchar_t* title) {
    OPENFILENAMEW ofn = {0};
    wchar_t szFile[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = title;

    if (GetOpenFileNameW(&ofn) == TRUE) {
        return ofn.lpstrFile;
    }
    return L"";
}

std::wstring ShowSaveFileDialog(HWND hwnd, const wchar_t* filter, const wchar_t* title, const wchar_t* defaultName) {
    OPENFILENAMEW ofn = {0};
    wchar_t szFile[MAX_PATH] = {0};
    if (defaultName) wcsncpy_s(szFile, defaultName, MAX_PATH -1);

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_EXPLORER;
    ofn.lpstrTitle = title;
    ofn.lpstrDefExt = L"bin";


    if (GetSaveFileNameW(&ofn) == TRUE) {
        return ofn.lpstrFile;
    }
    return L"";
}

std::wstring ShowBrowseFolderDialog(HWND hwnd, const wchar_t* title) {
    BROWSEINFOW bi = {0};
    bi.hwndOwner = hwnd;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpszTitle = title;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    wchar_t szPath[MAX_PATH] = {0};

    if (pidl != NULL) {
        if (SHGetPathFromIDListW(pidl, szPath)) {
            CoTaskMemFree(pidl);
            return szPath;
        }
        CoTaskMemFree(pidl);
    }
    return L"";
}