#include "dbg.h"

static int map_path_matches_debuggee(const char *path)
{
    if (!path || !path[0])
        return 0;

    if (!strcmp(path, debuggee_realpath))
        return 1;

    if (!strcmp(file_basename(path), file_basename(debuggee_realpath)))
        return 1;

    return 0;
}

int update_load_base(void)
{
    dbg.load_base = 0;

    if (!dbg.is_pie)
        return 0;

    char maps_path[64];

    snprintf(maps_path, sizeof(maps_path),
             "/proc/%d/maps", dbg.pid);

    FILE *fp = fopen(maps_path, "r");

    if (!fp) {
        perror("fopen maps");
        return -1;
    }

    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start;
        unsigned long end;
        unsigned long offset;
        char perms[5] = {0};
        char path[512] = {0};

        int n = sscanf(line,
                       "%lx-%lx %4s %lx %*s %*s %511s",
                       &start, &end, perms, &offset, path);

        if (n < 4)
            continue;

        if (n == 5 && strchr(perms, 'x') &&
            map_path_matches_debuggee(path)) {
            dbg.load_base = start - offset;
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}
void load_symbols(char *path)
{
    sym_count = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (map == MAP_FAILED) {
        perror("mmap");
        return;
    }

    Elf64_Ehdr *ehdr = map;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "not an ELF file\n");
        munmap(map, st.st_size);
        return;
    }

    dbg.is_pie = (ehdr->e_type == ET_DYN);

    Elf64_Shdr *shdrs =
        (Elf64_Shdr *)((char *)map + ehdr->e_shoff);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = &shdrs[i];
            strtab = &shdrs[symtab->sh_link];
            break;
        }
    }

    if (!symtab || !strtab) {
        munmap(map, st.st_size);
        return;
    }

    Elf64_Sym *syms =
        (Elf64_Sym *)((char *)map + symtab->sh_offset);
    char *strs = (char *)map + strtab->sh_offset;
    int count = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < count && sym_count < MAX_SYMBOLS; i++) {
        Elf64_Sym *sym = &syms[i];
        unsigned char type = ELF64_ST_TYPE(sym->st_info);

        if (type != STT_FUNC && type != STT_OBJECT)
            continue;

        if (sym->st_shndx == SHN_UNDEF || sym->st_value == 0)
            continue;

        if (sym->st_name == 0)
            continue;

        strncpy(symbols[sym_count].name,
                strs + sym->st_name,
                sizeof(symbols[sym_count].name) - 1);
        symbols[sym_count].name[
            sizeof(symbols[sym_count].name) - 1] = '\0';
        symbols[sym_count].addr = sym->st_value;
        symbols[sym_count].size = sym->st_size;
        symbols[sym_count].type = type;
        sym_count++;
    }

    munmap(map, st.st_size);
}

void show_symbols(void)
{
    if (sym_count == 0) {
        printf("no symbols loaded (use run first)\n");
        return;
    }

    printf("Num  Address            Size   Type  Name\n");

    for (int i = 0; i < sym_count; i++) {
        const char *kind =
            symbols[i].type == STT_FUNC ? "func" : "obj";
        unsigned long addr = symbols[i].addr;

        if (dbg.running)
            addr = to_runtime_addr(addr);

        printf("%-4d 0x%-16lx ", i + 1, addr);

        if (symbols[i].size)
            printf("%-6lu ", symbols[i].size);
        else
            printf("%-6s ", "-");

        printf("%-5s %s\n", kind, symbols[i].name);
    }

    printf("%d symbol(s)\n", sym_count);
}

const symbol_t *lookup_symbol_entry(const char *name)
{
    for (int i = 0; i < sym_count; i++) {
        if (!strcmp(symbols[i].name, name))
            return &symbols[i];
    }

    return NULL;
}

int lookup_symbol(const char *name, unsigned long *addr)
{
    const symbol_t *sym = lookup_symbol_entry(name);

    if (!sym)
        return -1;

    *addr = sym->addr;
    return 0;
}

int lookup_function_body_addr(const symbol_t *sym,
                                     unsigned long *addr)
{
    if (!sym || sym->type != STT_FUNC)
        return -1;

    unsigned long start = sym->addr;
    unsigned long end = sym->size ? start + sym->size : 0;
    unsigned long best = 0;

    for (int i = 0; i < line_entry_count; i++) {
        unsigned long line_addr = line_entries[i].addr;

        if (line_addr <= start)
            continue;

        if (end != 0 && line_addr >= end)
            continue;

        if (best == 0 || line_addr < best)
            best = line_addr;
    }

    if (best == 0)
        return -1;

    *addr = best;
    return 0;
}
const symbol_t *lookup_function_symbol(unsigned long addr)
{
    const symbol_t *best = NULL;

    addr = to_debug_addr(addr);

    for (int i = 0; i < sym_count; i++) {
        if (symbols[i].type != STT_FUNC)
            continue;

        if (symbols[i].addr > addr)
            continue;

        if (symbols[i].size > 0 &&
            addr >= symbols[i].addr + symbols[i].size)
            continue;

        if (symbols[i].size == 0 &&
            addr != symbols[i].addr)
            continue;

        if (!best || symbols[i].addr > best->addr)
            best = &symbols[i];
    }

    return best;
}
