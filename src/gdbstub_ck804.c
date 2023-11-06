#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "elf.h"
#include "gdbstub.h"

/**
  * w800 addr layout:
  * flash: 0x08000000 ~ 0x0FFFFFFF
  * sram : 0x20000000 ~ 0x20047FFF
  * psram: 0x30000000 ~ 0x307FFFFF
  * reg  : 0x40000000 ~ 0x4003BFFF
  */

#define MEM_SIZE            (0x48000)

#define MEM_BASE            (0x20000000)
#define FLASE_BASE          (0x0800A400)

#define GENERAL_REG_NUM	    32
#define GENERAL_REG_SIZE    4
#define ALL_REG_NUM         231

struct mem {
    uint8_t *mem;
    uint32_t mem_size;
    uint32_t flash_base;
    uint32_t flash_size;
    uint8_t *code;
    uint32_t code_size;
};

struct ck804 {
    struct mem m;

    uint32_t x[ALL_REG_NUM];

    gdbstub_t gdbstub;
};

static void emu_init(struct ck804 *ck804)
{
    memset(ck804, 0, sizeof(struct ck804));

    /* get r16-r31 */
    ck804->x[16] = 0x16161616;
    ck804->x[17] = 0x17171717;
    ck804->x[18] = 0x18181818;
    ck804->x[19] = 0x19191919;
    ck804->x[20] = 0x20202020;
    ck804->x[21] = 0x21212121;
    ck804->x[22] = 0x22222222;
    ck804->x[23] = 0x23232323;
    ck804->x[24] = 0x24242424;
    ck804->x[25] = 0x25252525;
    ck804->x[26] = 0x26262626;
    ck804->x[27] = 0x27272727;
    ck804->x[28] = 0x28282828;
    ck804->x[29] = 0x29292929;
    ck804->x[30] = 0x30303030;
    ck804->x[31] = 0x31313131;

    ck804->m.flash_base = FLASE_BASE;
}

static int init_mem(struct ck804 *ck804, const char *elf_file, const char *ramdum_file)
{
    struct mem *m = &(ck804->m);

    if (!ramdum_file || !elf_file)
    {
        return -1;
    }

    /* prase ramdum file */
    FILE *fp = fopen(ramdum_file, "rb");
    if (!fp)
    {
        return -1;
    }

    /* get r0-r15 */
    uint32_t read_size = fread(&(ck804->x[0]), sizeof(uint8_t), 64, fp);
    if (read_size != 64)
    {
        fprintf(stderr, "Fail to read r0-r15 in the ramdump file.\n");
        fclose(fp);
        return -1;
    }

    /* get psr */
    read_size = fread(&(ck804->x[89]), sizeof(uint8_t), 4, fp);
    if (read_size != 4)
    {
        fprintf(stderr, "Fail to read psr in the ramdump file.\n");
        fclose(fp);
        return -1;
    }

    /* get pc */
    read_size = fread(&(ck804->x[72]), sizeof(uint8_t), 4, fp);
    if (read_size != 4)
    {
        fprintf(stderr, "Fail to read pc in the ramdump file.\n");
        fclose(fp);
        return -1;
    }

    m->mem = malloc(MEM_SIZE);
    if (!m->mem)
    {
        fclose(fp);
        return -1;
    }

    /* get ram data */
    memset(m->mem, 0, MEM_SIZE);
    read_size = fread(m->mem, sizeof(uint8_t), MEM_SIZE, fp);
    if (read_size != MEM_SIZE)
    {
        fprintf(stderr, "Fail to read ram in the %s file.\n", ramdum_file);
        fclose(fp);
        free(m->mem);
        return -1;
    }
    fclose(fp);
    m->mem_size = read_size;

    /* prase elf file */
    fp = fopen(elf_file, "rb");
    if (!fp)
    {
        free(m->mem);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    uint32_t sz = ftell(fp) * sizeof(uint8_t);
    rewind(fp);

    uint8_t *elf = malloc(sz);
    if (!elf)
    {
        fclose(fp);
        free(m->mem);
        return -1;
    }

    read_size = fread(elf, sizeof(uint8_t), sz, fp);
    fclose(fp);
    if (read_size != sz)
    {
        fprintf(stderr, "Fail to read elf in the %s file.\n", elf);
        free(m->mem);
        return -1;
    }

    uint32_t      section_num    = *(Elf32_Half*)(elf + sizeof(Elf32_Ehdr) - 4);
    Elf32_Ehdr *elf_header     =  (Elf32_Ehdr*)elf;
    Elf32_Half  shstrndx       =   elf_header->e_shstrndx;
    Elf32_Shdr *section_header =  (Elf32_Shdr*)(elf + elf_header->e_shoff);
    Elf32_Shdr *shstr          =  (Elf32_Shdr*)(section_header + shstrndx);
    char       *shstrbuff      =  (char *)(elf + shstr->sh_offset);
    Elf32_Off	sh_offset[2]   = {0, 0};
    Elf32_Word	sh_size[2]     = {0, 0};

    /* get in flash sections info */
    for (uint32_t i = 0; i < section_num; i++)
    {
        if ((section_header[i].sh_type == SHT_PROGBITS) && (0 != section_header[i].sh_addr))
        {
            if (!strcmp((char *)(section_header[i].sh_name + shstrbuff), ".text"))
            {
                sh_offset[0] = section_header[i].sh_offset;
                sh_size[0]   = section_header[i].sh_size;
                m->flash_base = section_header[i].sh_addr;
            }
            else if (!strcmp((char *)(section_header[i].sh_name + shstrbuff), ".rodata"))
            {
                sh_offset[1] = section_header[i].sh_offset;
                sh_size[1]   = section_header[i].sh_size;
            }

            if (sh_offset[0] && sh_offset[1])
            {
                m->flash_size = sh_size[0] + sh_size[1];
                break;
            }
        }
    }

    if (!m->flash_size)
    {
        free(m->mem);
        free(elf);
        return -1;
    }

    m->code = malloc(m->flash_size);
    if (!m->code) {
        free(m->mem);
        free(elf);
        return -1;
    }

    /* get flash code */
    memset(m->code, 0, m->flash_size);
    memcpy(m->code, elf + sh_offset[0], sh_size[0]);
    memcpy(m->code + sh_size[0], elf + sh_offset[1], sh_size[1]);

    free(elf);
    m->code_size = m->flash_size;

    return 0;
}

static void free_mem(struct mem *m)
{
    free(m->mem);
    free(m->code);
}

static int emu_read_reg(void *args, int regno, uint32_t *reg_value)
{
    struct ck804 *ck804 = (struct ck804 *)args;

    if (regno > ALL_REG_NUM)
    {
        return EFAULT;
    }

    *reg_value = ck804->x[regno];

    return 0;
}

static int emu_write_reg(void *args, int regno, uint32_t data)
{
    struct ck804 *ck804 = (struct ck804 *)args;

    if (regno > ALL_REG_NUM)
    {
        return EFAULT;
    }

    ck804->x[regno] = data;

    return 0;
}

static int emu_read_mem(void *args, uint32_t addr, uint32_t len, void *val)
{
    struct ck804 *ck804 = (struct ck804 *)args;
    uint32_t local_addr;

    if (addr >= MEM_BASE)
    {
        local_addr = addr - MEM_BASE;
        if (local_addr + len > MEM_SIZE)
        {
            return 0;//EFAULT;
        }
        memcpy(val, (void *) ck804->m.mem + local_addr, len);
    }
    else
    {
        local_addr = addr - ck804->m.flash_base;
        if (local_addr + len > ck804->m.flash_size)
        {
            return 0;//EFAULT;
        }
        memcpy(val, (void *) ck804->m.code + local_addr, len);
    }

    return 0;
}

static int emu_write_mem(void *args, uint32_t addr, uint32_t len, void *val)
{
    struct ck804 *ck804 = (struct ck804 *)args;
    uint32_t local_addr;

    if (addr >= MEM_BASE)
    {
        local_addr = addr - MEM_BASE;
        if (local_addr + len > MEM_SIZE)
        {
            return EFAULT;
        }
        memcpy((void *) ck804->m.mem + local_addr, val, len);
    }
    else
    {
        local_addr = addr - ck804->m.flash_base;
        if (local_addr + len > ck804->m.flash_size)
        {
            return EFAULT;
        }
        memcpy((void *) ck804->m.code + local_addr, val, len);
    }

    return 0;
}

static gdb_action_t emu_cont(void *args)
{
    (void)args;

    return ACT_NONE;
}

static gdb_action_t emu_stepi(void *args)
{
    (void)args;

    return ACT_NONE;
}

static bool emu_set_bp(void *args, uint32_t addr, bp_type_t type)
{
    (void)args;
    (void)addr;
    (void)type;

    return false;
}

static bool emu_del_bp(void *args, uint32_t addr, bp_type_t type)
{
    (void)args;
    (void)addr;
    (void)type;

    return false;
}

static void emu_on_interrupt(void *args)
{
    (void)args;
}

struct target_ops emu_ops = {
    .read_reg  = emu_read_reg,
    .write_reg = emu_write_reg,
    .read_mem  = emu_read_mem,
    .write_mem = emu_write_mem,
    .cont      = emu_cont,
    .stepi     = emu_stepi,
    .set_bp    = emu_set_bp,
    .del_bp    = emu_del_bp,
    .on_interrupt = emu_on_interrupt,
};

int main(int argc, char *argv[])
{
    if ((argc != 3) && (argc != 4))
    {
	    printf("%s <elf_file> <ramdump_file> [port]\n", basename(argv[0]));

        return -1;
    }

    struct ck804 ck804;
    emu_init(&ck804);

    if (init_mem(&ck804, argv[1], argv[2]) == -1)
    {
        return -1;
    }

    char ip_port[32];
    if (argc == 4)
        sprintf(ip_port, "%s:%s", "127.0.0.1", argv[3]);
    else
        sprintf(ip_port, "%s:%hu", "127.0.0.1", 1234);

    if (!gdbstub_init(&ck804.gdbstub, &emu_ops,
                      (arch_info_t) {
                          .reg_num = GENERAL_REG_NUM,
                          .reg_byte = GENERAL_REG_SIZE,
                          .target_desc = TARGET_CSKY_CK804,
                      },
                      ip_port))
    {
        fprintf(stderr, "Fail to create socket.\n");

        return -1;
    }

    if (!gdbstub_run(&ck804.gdbstub, (void *) &ck804))
    {
        fprintf(stderr, "Fail to run in debug mode.\n");
        return -1;
    }

    gdbstub_close(&ck804.gdbstub);

    free_mem(&ck804.m);

    return 0;
}
