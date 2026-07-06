#include "dbg.h"

uint64_t read_uleb128(const uint8_t *data, size_t len, size_t *off)
{
    uint64_t result = 0;
    unsigned int shift = 0;

    while (*off < len) {
        uint8_t byte = data[(*off)++];
        result |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0)
            return result;
        shift += 7;
    }

    return result;
}

int64_t read_sleb128(const uint8_t *data, size_t len, size_t *off)
{
    uint64_t result = 0;
    unsigned int shift = 0;

    while (*off < len) {
        uint8_t byte = data[(*off)++];
        result |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40))
                result |= -(1ULL << (shift + 7));
            return (int64_t)result;
        }
        shift += 7;
    }

    return 0;
}
int parse_on_off(const char *name, int *value)
{
    if (!strcmp(name, "on") || !strcmp(name, "1") || !strcmp(name, "yes")) {
        *value = 1;
        return 0;
    }

    if (!strcmp(name, "off") || !strcmp(name, "0") || !strcmp(name, "no")) {
        *value = 0;
        return 0;
    }

    return -1;
}

void trim_line(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                       s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}
const char *file_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash ? slash + 1 : path;
}

int file_matches(const char *entry_file, const char *query)
{
    if (!strcmp(entry_file, query))
        return 1;

    if (!strcmp(file_basename(entry_file), query))
        return 1;

    return 0;
}

unsigned long to_debug_addr(unsigned long addr)
{
    if (dbg.is_pie && dbg.load_base != 0 && addr >= dbg.load_base)
        return addr - dbg.load_base;

    return addr;
}

unsigned long to_runtime_addr(unsigned long addr)
{
    if (dbg.is_pie && dbg.load_base != 0 && addr < dbg.load_base)
        return addr + dbg.load_base;

    return addr;
}
