#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    FILE_HEADER_SIZE = 55,
    BACKUP_HEADER_SIZE = 9,
    PART1_ORIGIN = 0x8528,
    PART2_ORIGIN = 0x8D24,
    NATIVE_ORIGIN = 0x8D4E,
    TARGET_BASE = 0x90FF,
    LAST_ENTRY_ORIGIN = 0x914A,
    CMD_SHADOW = 0x8BDF,
    CMD_SHADOW_SIZE = 128,
    P_TEMP = 0x8D18,
    VAT_TOP = 0xFE6E,
    STOCK_P_TEMP = 0xFD95,
    BURN_P_TEMP = 0xFD96,
    SHELL_OLD_CONTENT_LENGTH = 0x03DD,
    SHELL_FINAL_CONTENT_LENGTH = 0x03D9
};

static const uint8_t ti82_signature[11] = {
    '*', '*', 'T', 'I', '8', '2', '*', '*', 0x1A, 0x0A, 0x00
};

struct blob {
    uint8_t *data;
    size_t size;
};

struct backup {
    uint8_t comment[42];
    uint16_t header_size;
    uint8_t variable_type;
    uint16_t memory_address;
    struct blob part[3];
};

struct options {
    const char *template_path;
    const char *native_path;
    const char *output_path;
    const char *comment;
    const char *profile;
};

static void fail(const char *message)
{
    fprintf(stderr, "mk82b: %s\n", message);
    exit(EXIT_FAILURE);
}

static void fail_path(const char *action, const char *path)
{
    fprintf(stderr, "mk82b: %s %s: %s\n", action, path, strerror(errno));
    exit(EXIT_FAILURE);
}

static uint16_t read_le16(const uint8_t *data)
{
    return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static void write_le16(uint8_t *data, const uint16_t value)
{
    data[0] = (uint8_t)(value & 0xFF);
    data[1] = (uint8_t)(value >> 8);
}

static struct blob read_file(const char *path)
{
    struct blob result = {NULL, 0};

    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        fail_path("cannot open", path);
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fail_path("cannot seek", path);
    }
    const long length = ftell(file);
    if (length < 0) {
        fail_path("cannot measure", path);
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fail_path("cannot rewind", path);
    }
    result.size = (size_t)length;
    result.data = malloc(result.size == 0 ? 1 : result.size);
    if (result.data == NULL) {
        fail("out of memory");
    }
    if (result.size != 0 && fread(result.data, 1, result.size, file) != result.size) {
        fail_path("cannot read", path);
    }
    if (fclose(file) != 0) {
        fail_path("cannot close", path);
    }
    return result;
}

static void write_file(const char *path, const uint8_t *data, const size_t size)
{
    FILE *file = fopen(path, "wb");

    if (file == NULL) {
        fail_path("cannot create", path);
    }
    if (size != 0 && fwrite(data, 1, size, file) != size) {
        fail_path("cannot write", path);
    }
    if (fclose(file) != 0) {
        fail_path("cannot close", path);
    }
}

static uint16_t additive_checksum(const uint8_t *data, const size_t size)
{
    uint32_t sum = 0;

    for (size_t index = 0; index < size; ++index) {
        sum += data[index];
    }
    return (uint16_t)sum;
}

static struct backup parse_backup(const struct blob *image)
{
    struct backup result;
    size_t offset = FILE_HEADER_SIZE;
    uint16_t lengths[3];

    memset(&result, 0, sizeof(result));
    if (image->size < FILE_HEADER_SIZE + BACKUP_HEADER_SIZE + 8) {
        fail("backup template is truncated");
    }
    if (memcmp(image->data, ti82_signature, sizeof(ti82_signature)) != 0) {
        fail("backup template has an unexpected TI-82 signature");
    }
    if (read_le16(image->data + 53) != image->size - 57) {
        fail("backup template data-section length is invalid");
    }
    const uint16_t expected_checksum = read_le16(image->data + image->size - 2);
    if (additive_checksum(image->data + FILE_HEADER_SIZE, image->size - FILE_HEADER_SIZE - 2) != expected_checksum) {
        fail("backup template checksum is invalid");
    }

    memcpy(result.comment, image->data + 11, sizeof(result.comment));
    result.header_size = read_le16(image->data + offset);
    offset += 2;
    if (result.header_size != BACKUP_HEADER_SIZE) {
        fail("backup template does not use a 9-byte backup header");
    }
    lengths[0] = read_le16(image->data + offset);
    result.variable_type = image->data[offset + 2];
    lengths[1] = read_le16(image->data + offset + 3);
    lengths[2] = read_le16(image->data + offset + 5);
    result.memory_address = read_le16(image->data + offset + 7);
    offset += BACKUP_HEADER_SIZE;

    for (size_t index = 0; index < 3; ++index) {
        if (offset + 2 > image->size - 2 || read_le16(image->data + offset) != lengths[index]) {
            fail("backup template has an invalid repeated part length");
        }
        offset += 2;
        if (offset + lengths[index] > image->size - 2) {
            fail("backup template part is truncated");
        }
        result.part[index].size = lengths[index];
        result.part[index].data = malloc(lengths[index] == 0 ? 1 : lengths[index]);
        if (result.part[index].data == NULL) {
            fail("out of memory");
        }
        memcpy(result.part[index].data, image->data + offset, lengths[index]);
        offset += lengths[index];
    }
    if (offset != image->size - 2) {
        fail("backup template has trailing data");
    }
    return result;
}

static void free_backup(struct backup *backup)
{
    for (size_t index = 0; index < 3; ++index) {
        free(backup->part[index].data);
        backup->part[index].data = NULL;
        backup->part[index].size = 0;
    }
}

static struct blob encode_backup(const struct backup *backup, const char *comment)
{
    struct blob image = {NULL, 0};
    size_t comment_size = strlen(comment);

    if (comment_size > 42) {
        comment_size = 42;
    }
    const size_t section_size = backup->part[0].size + backup->part[1].size + backup->part[2].size + 17;
    if (section_size > UINT16_MAX) {
        fail("backup data section is too large");
    }
    image.size = FILE_HEADER_SIZE + section_size + 2;
    image.data = calloc(image.size, 1);
    if (image.data == NULL) {
        fail("out of memory");
    }

    memcpy(image.data, ti82_signature, sizeof(ti82_signature));
    memcpy(image.data + 11, comment, comment_size);
    write_le16(image.data + 53, (uint16_t)section_size);
    size_t offset = FILE_HEADER_SIZE;
    write_le16(image.data + offset, BACKUP_HEADER_SIZE);
    offset += 2;
    write_le16(image.data + offset, (uint16_t)backup->part[0].size);
    image.data[offset + 2] = backup->variable_type;
    write_le16(image.data + offset + 3, (uint16_t)backup->part[1].size);
    write_le16(image.data + offset + 5, (uint16_t)backup->part[2].size);
    write_le16(image.data + offset + 7, backup->memory_address);
    offset += BACKUP_HEADER_SIZE;

    for (size_t index = 0; index < 3; ++index) {
        write_le16(image.data + offset, (uint16_t)backup->part[index].size);
        offset += 2;
        memcpy(image.data + offset, backup->part[index].data, backup->part[index].size);
        offset += backup->part[index].size;
    }
    if (offset != image.size - 2) {
        fail("internal backup size error");
    }
    write_le16(image.data + offset, additive_checksum(image.data + FILE_HEADER_SIZE, offset - FILE_HEADER_SIZE));
    return image;
}

static size_t find_unique(const uint8_t *data, const size_t size,
                          const uint8_t *needle, const size_t needle_size,
                          const char *description)
{
    size_t found = SIZE_MAX;

    if (needle_size == 0 || needle_size > size) {
        fail("invalid search pattern");
    }
    for (size_t index = 0; index + needle_size <= size; ++index) {
        if (memcmp(data + index, needle, needle_size) == 0) {
            if (found != SIZE_MAX) {
                fprintf(stderr, "mk82b: %s is not unique\n", description);
                exit(EXIT_FAILURE);
            }
            found = index;
        }
    }
    if (found == SIZE_MAX) {
        fprintf(stderr, "mk82b: cannot find %s\n", description);
        exit(EXIT_FAILURE);
    }
    return found;
}

static void replace_unique(uint8_t *data, const size_t size,
                           const uint8_t *before, const uint8_t *after,
                           const size_t pattern_size, const char *description)
{
    const size_t offset = find_unique(data, size, before, pattern_size, description);
    memcpy(data + offset, after, pattern_size);
}

static void configure_parser(const struct backup *backup, const char *profile)
{
    static const uint8_t expected_prefix[] = {
        0x5C, 0x4C, 0x10, 0x31, 0x2B, 0x31, 0x04, 0x5C, 0x4B, 0x10,
        0x35, 0x32, 0x2B, 0x31, 0x3F, 0x31, 0x70, 0x3B, 0x31, 0x33,
        0x04, 0x5C, 0x4B, 0x10, 0x35, 0x31, 0x2B, 0x34, 0x31, 0x3F,
        0xE0, 0x31, 0x2B, 0x31, 0x2B, 0x2A, 0x3F, 0xD9, 0x3F, 0x3F
    };
    static const uint8_t source_first[] = {0x5C, 0x4B, 0x10, 0x35, 0x32, 0x2B, 0x31, 0x3F};
    static const uint8_t target_first[] = {0x5C, 0x4B, 0x10, 0x35, 0x32, 0x2B, 0x36, 0x3F};
    static const uint8_t source_second[] = {0x5C, 0x4B, 0x10, 0x35, 0x31, 0x2B, 0x34, 0x31, 0x3F};
    static const uint8_t target_second[] = {0x5C, 0x4B, 0x10, 0x35, 0x31, 0x2B, 0x33, 0x37, 0x3F};
    static const uint8_t source_pointer[] = {0x4B, 0x5C, 0x01, 0xC0};
    static const uint8_t target_pointer[] = {0x4B, 0x5C, 0x11, 0xB6};
    const size_t prefix_offset = 2;
    const size_t prefix_size = NATIVE_ORIGIN - PART2_ORIGIN - 2;

    if (backup->part[1].size < prefix_offset + prefix_size ||
        memcmp(backup->part[1].data + prefix_offset, expected_prefix, sizeof(expected_prefix)) != 0) {
        fail("stock CrASH parser prefix preimage does not match");
    }
    (void)find_unique(backup->part[2].data, backup->part[2].size,
                      source_pointer, sizeof(source_pointer),
                      "stock fake-matrix VAT pointer");

    if (strcmp(profile, "19.006") == 0) {
        replace_unique(backup->part[1].data + prefix_offset, prefix_size,
                       source_first, target_first, sizeof(source_first),
                       "first parser matrix reference");
        replace_unique(backup->part[1].data + prefix_offset, prefix_size,
                       source_second, target_second, sizeof(source_second),
                       "second parser matrix reference");
        replace_unique(backup->part[2].data, backup->part[2].size,
                       source_pointer, target_pointer, sizeof(source_pointer),
                       "stock fake-matrix VAT pointer");
    } else if (strcmp(profile, "15.0-18.0") != 0 && strcmp(profile, "19.0") != 0) {
        fail("unknown ROM profile");
    }
}

static void install_native(struct backup *backup, const struct blob *native)
{
    static const uint8_t stock_vat_prefix[] = {'H', 'S', 'A', 'R', 'C', 5, 0x8D, 0x24, 0x06};
    static const uint8_t burn_vat_prefix[] = {'N', 'R', 'U', 'B', 4, 0x8D, 0x24, 0x06};
    static const uint8_t stock_last_entry[] = {6, 0, 0x5F, 'C', 'R', 'A', 'S', 'H'};
    static const uint8_t burn_last_entry[] = {5, 0, 0x5F, 'B', 'U', 'R', 'N'};
    static const uint8_t stock_splash[] =
        "\xE1\xD9 CrASH v1.6 \xD9\xE1"
        "                "
        "    May 1999    "
        "                "
        " Hideaki  Omuro "
        "   Jeff Mears   "
        "                "
        "                ";
    static const uint8_t burn_splash[] =
        "\xE1\xD9  BuRN 1.0  \xD9\xE1"
        "                "
        " November  2026 "
        "                "
        " Hideaki  Omuro "
        "   Jeff Mears   "
        "CVSoft & Adriweb"
        "                ";
    const size_t native_offset = NATIVE_ORIGIN - PART2_ORIGIN;
    const size_t tail_offset = TARGET_BASE - PART2_ORIGIN;
    const size_t ptemp_offset = P_TEMP - PART1_ORIGIN;
    const size_t splash_offset = CMD_SHADOW - PART1_ORIGIN;
    const size_t expected_last_entry_offset = LAST_ENTRY_ORIGIN - PART2_ORIGIN;

    if (sizeof(stock_splash) != CMD_SHADOW_SIZE + 1 ||
        sizeof(burn_splash) != CMD_SHADOW_SIZE + 1) {
        fail("internal splash size invariant failed");
    }
    if (native->size != TARGET_BASE - NATIVE_ORIGIN) {
        fail("linked native shell has the wrong size");
    }
    if (backup->variable_type != 0x0F ||
        backup->memory_address != PART2_ORIGIN ||
        backup->part[0].size != PART2_ORIGIN - PART1_ORIGIN) {
        fail("stock CrASH backup layout is unexpected");
    }
    if (backup->part[1].size < tail_offset + 4 ||
        read_le16(backup->part[1].data) != SHELL_OLD_CONTENT_LENGTH) {
        fail("stock CrASH shell preimage is unexpected");
    }
    if (memcmp(backup->part[1].data + tail_offset, "\0\0\0\0", 4) != 0) {
        fail("stock CrASH removable tail is not zero");
    }
    if (ptemp_offset + 2 > backup->part[0].size ||
        read_le16(backup->part[0].data + ptemp_offset) != STOCK_P_TEMP) {
        fail("stock CrASH pTemp preimage is unexpected");
    }
    if (splash_offset + CMD_SHADOW_SIZE > backup->part[0].size ||
        memcmp(backup->part[0].data + splash_offset,
               stock_splash, CMD_SHADOW_SIZE) != 0) {
        fail("stock CrASH command-shadow splash preimage is unexpected");
    }
    if (backup->part[2].size < sizeof(stock_vat_prefix) ||
        memcmp(backup->part[2].data, stock_vat_prefix, sizeof(stock_vat_prefix)) != 0) {
        fail("stock CrASH VAT entry preimage is unexpected");
    }

    const size_t last_entry_offset = find_unique(
        backup->part[1].data, backup->part[1].size,
        stock_last_entry, sizeof(stock_last_entry),
        "stock tokenized last entry");
    if (last_entry_offset != expected_last_entry_offset) {
        fail("stock tokenized last entry is at an unexpected address");
    }

    write_le16(backup->part[0].data + ptemp_offset, BURN_P_TEMP);
    memcpy(backup->part[0].data + splash_offset,
           burn_splash, CMD_SHADOW_SIZE);
    memcpy(backup->part[1].data + native_offset, native->data, native->size);
    memset(backup->part[1].data + tail_offset, 0, 4);
    memcpy(backup->part[1].data + last_entry_offset, burn_last_entry, sizeof(burn_last_entry));
    /* Preserve FPBase and the parser exploit's RAM geometry; the shorter
       command leaves one zero padding byte rather than compacting part 2. */
    backup->part[1].data[last_entry_offset + sizeof(burn_last_entry)] = 0;

    uint8_t* new_part3 = malloc(backup->part[2].size - 1);
    if (new_part3 == NULL) {
        fail("out of memory");
    }
    memcpy(new_part3, burn_vat_prefix, sizeof(burn_vat_prefix));
    memcpy(new_part3 + sizeof(burn_vat_prefix),
           backup->part[2].data + sizeof(stock_vat_prefix),
           backup->part[2].size - sizeof(stock_vat_prefix));
    free(backup->part[2].data);
    backup->part[2].data = new_part3;
    --backup->part[2].size;

    if (VAT_TOP - backup->part[2].size != BURN_P_TEMP ||
        (NATIVE_ORIGIN - PART2_ORIGIN - 2) + native->size != SHELL_FINAL_CONTENT_LENGTH) {
        fail("rebuilt BuRN layout invariant failed");
    }
}

static struct options parse_options(const int argc, char **argv)
{
    struct options result = {NULL, NULL, NULL, NULL, NULL};

    for (int index = 1; index < argc; ++index) {
        const char *argument = argv[index];
        const char **destination = NULL;

        if (strcmp(argument, "--template") == 0) {
            destination = &result.template_path;
        } else if (strcmp(argument, "--native") == 0) {
            destination = &result.native_path;
        } else if (strcmp(argument, "--output") == 0) {
            destination = &result.output_path;
        } else if (strcmp(argument, "--comment") == 0) {
            destination = &result.comment;
        } else if (strcmp(argument, "--profile") == 0) {
            destination = &result.profile;
        } else {
            fprintf(stderr, "mk82b: unknown argument: %s\n", argument);
            exit(EXIT_FAILURE);
        }
        if (++index >= argc) {
            fail("missing option value");
        }
        const char* value = argv[index];
        *destination = value;
    }
    if (result.template_path == NULL || result.native_path == NULL ||
        result.output_path == NULL || result.comment == NULL || result.profile == NULL) {
        fail("usage: mk82b --template FILE --native FILE --output FILE --comment TEXT --profile {15.0-18.0|19.0|19.006}");
    }
    return result;
}

int main(const int argc, char **argv)
{
    const struct options options = parse_options(argc, argv);
    const struct blob template_image = read_file(options.template_path);
    const struct blob native = read_file(options.native_path);
    struct backup backup = parse_backup(&template_image);
    struct blob output;
    struct backup check;

    configure_parser(&backup, options.profile);
    install_native(&backup, &native);
    output = encode_backup(&backup, options.comment);
    check = parse_backup(&output);
    if (check.part[1].size < TARGET_BASE - PART2_ORIGIN ||
        memcmp(check.part[1].data + NATIVE_ORIGIN - PART2_ORIGIN, native.data, native.size) != 0) {
        fail("encoded backup does not contain the linked native shell");
    }
    write_file(options.output_path, output.data, output.size);

    free_backup(&check);
    free_backup(&backup);
    free(output.data);
    free(native.data);
    free(template_image.data);
    return EXIT_SUCCESS;
}
