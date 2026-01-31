#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char short_opt;
    char* long_opt;
    char* default_value;
    int is_flag;  // 1 = flag option (no value), 0 = option with value
} xArgsCFG;

typedef struct HashNode {
    char* key;
    char* value;
    struct HashNode* next;
} HashNode;

#define HASH_SIZE 64
#define strndup(str) str?strcpy((char*)malloc(strlen(str) + 1), str):NULL

static HashNode* hash_table[HASH_SIZE];
static int hash_initialized = 0;
static xArgsCFG* internal_configs = NULL;
static int internal_count = 0;
static char other_args[2048];

static void hash_init() {
    if (!hash_initialized) {
        for (int i = 0; i < HASH_SIZE; i++) {
            hash_table[i] = NULL;
        }
        hash_initialized = 1;
    }
}

static unsigned int hash(const char* str) {
    unsigned int h = 0;
    while (*str) h = h * 31 + *str++;
    return h % HASH_SIZE;
}

static void hash_set(const char* key, const char* value) {
    hash_init();
    unsigned int idx = hash(key);

    HashNode* node = (HashNode*)malloc(sizeof(HashNode));
    node->key = strndup(key);
    node->value = strndup(value);
    node->next = hash_table[idx];
    hash_table[idx] = node;
}

static const char* hash_get(const char* key) {
    hash_init();
    unsigned int idx = hash(key);
    HashNode* node = hash_table[idx];
    while (node) {
        if (strcmp(node->key, key) == 0) return node->value;
        node = node->next;
    }
    return NULL;
}

static xArgsCFG* find_config(const char* key) {
    size_t len = strlen(key);

    if (len == 1) {
        char s = key[0];
        for (int i = 0; i < internal_count; i++) {
            if (internal_configs[i].short_opt == s) return &internal_configs[i];
        }
    } else {
        for (int i = 0; i < internal_count; i++) {
            if (internal_configs[i].long_opt && strcmp(internal_configs[i].long_opt, key) == 0) return &internal_configs[i];
        }
    }
    return NULL;
}

static void set_config_value(xArgsCFG* config, const char* value) {
    char key[8];
    snprintf(key, sizeof(key), "-%c", config->short_opt);
    hash_set(key, value);
    if (config->long_opt) {
        hash_set(config->long_opt, value);
    }
}

static void add_to_other(const char* arg) {
    if (other_args[0]) strcat(other_args, " ");
    strcat(other_args, arg);
}

static int parse_arg(char* arg, int i, int argc, char* argv[], int is_long) {
    char* name_start = is_long ? arg + 2 : arg + 1;

    char* eq = strchr(name_start, '=');
    if (eq) {
        *eq = '\0';
        xArgsCFG* c = find_config(name_start);
        if (c) {
            set_config_value(c, eq + 1);
        } else {
            *eq = '=';
            add_to_other(arg);
        }
        return 0;
    }

    if (is_long) {
        xArgsCFG* c = NULL;

        for (int j = internal_count - 1; j >= 0; j--) {
            char* long_opt = internal_configs[j].long_opt;
            if (long_opt) {
                size_t len = strlen(long_opt);
                if (strncmp(name_start, long_opt, len) == 0) {
                    char* value_start = name_start + len;
                    if (*value_start) {
                        set_config_value(&internal_configs[j], value_start);
                        return 0;
                    } else {
                        c = &internal_configs[j];
                        break;
                    }
                }
            }
        }

        if (c) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                set_config_value(c, argv[i + 1]);
                return 1;
            } else {
                set_config_value(c, "");
            }
        } else {
            add_to_other(arg);
        }
    } else {
        char short_key[2] = {name_start[0], '\0'};
        xArgsCFG* c = find_config(short_key);
        if (c) {
            // Check if this is a flag option (no value)
            if (c->is_flag) {
                set_config_value(c, "");
            } else {
                char* value_start = name_start + 1;
                if (*value_start) {
                    set_config_value(c, value_start);
                } else if (i + 1 < argc && argv[i + 1][0] != '-') {
                    set_config_value(c, argv[i + 1]);
                    return 1;
                } else {
                    set_config_value(c, "");
                }
            }
        } else {
            add_to_other(arg);
        }
    }
    return 0;
}

void xargs_init(xArgsCFG* configs, int count, int argc, char* argv[]) {
    hash_init();
    internal_configs = configs;
    internal_count = count;
    other_args[0] = '\0';

    for (int i = 0; i < count; i++) {
        if (configs[i].short_opt && configs[i].default_value) {
            char key[8];
            snprintf(key, sizeof(key), "-%c", configs[i].short_opt);
            hash_set(key, configs[i].default_value);
        }
        if (configs[i].long_opt && configs[i].default_value) {
            hash_set(configs[i].long_opt, configs[i].default_value);
        }
    }

    int used = 0;
    for (int i = 1; i < argc; i += 1 + used) {
        used = 0;
        char* arg = argv[i];

        if (strncmp(arg, "--", 2) == 0) {
            used = parse_arg(arg, i, argc, argv, 1);
        } else if (arg[0] == '-' && arg[1]) {
            used = parse_arg(arg, i, argc, argv, 0);
        } else {
            add_to_other(arg);
        }
    }

    hash_set("_other_", other_args);
}

static inline const char* xargs_get_raw(const char* key) {
    size_t len = strlen(key);
    if (len == 1) {
        char hash_key[8];
        snprintf(hash_key, sizeof(hash_key), "-%c", key[0]);
        const char* val = hash_get(hash_key);
        if (val) return val;

        xArgsCFG* c = find_config(key);
        if (c && c->default_value) return c->default_value;
    } else {
        const char* val = hash_get(key);
        if (val) return val;

        xArgsCFG* c = find_config(key);
        if (c && c->default_value) return c->default_value;
    }
    return NULL;
}

const char* xargs_get_other() {
    return hash_get("_other_");
}

static inline const char* xargs_search(const char* key) {
    const char* other = hash_get("_other_");
    if (!other) return NULL;

    char* pos = strstr(other, key);
    if (!pos) return NULL;

    char* after_key = pos + strlen(key);

    if (*after_key == '=') {
        char* value_start = after_key + 1;
        while (*value_start == ' ') value_start++;

        char* space = strchr(value_start, ' ');
        if (space) {
            size_t len = space - value_start;
            char* result = (char*)malloc(len + 1);
            strncpy(result, value_start, len);
            result[len] = '\0';
            return result;
        } else {
            return strndup(value_start);
        }
    }

    while (*after_key == ' ') after_key++;

    char* space = strchr(after_key, ' ');
    if (space) {
        size_t len = space - after_key;
        char* result = (char*)malloc(len + 1);
        strncpy(result, after_key, len);
        result[len] = '\0';
        return result;
    } else {
        return strndup(after_key);
    }
}

const char* xargs_get(const char* key) {
    if (key == NULL || strlen(key)==0) return NULL;

    const char* val = xargs_get_raw(key);
    if (val) return val;
    if (strlen(key) == 1) {
        for (int i = 0; i < internal_count; i++) {
            if (internal_configs[i].short_opt==*key) {
                return NULL;
            }
        }
    }

    val = xargs_search(key);
    return val ? val : getenv(key);
}

void xargs_cleanup() {
    for (int i = 0; i < HASH_SIZE; i++) {
        HashNode* node = hash_table[i];
        while (node) {
            HashNode* next = node->next;
            free(node->key);
            free(node->value);
            free(node);
            node = next;
        }
        hash_table[i] = NULL;
    }
    hash_initialized = 0;
}

#ifdef _WIN32
#include <windows.h>
void console_set_consolas_font() {
    BOOL output_utf8 = SetConsoleOutputCP(CP_UTF8);
    BOOL input_utf8 = SetConsoleCP(CP_UTF8);
    if (!output_utf8 || !input_utf8) {
        fprintf(stderr, "Warning：Failed to set console output to UTF-8; Chinese text may appear garbled.\n");
    }

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return;
    }

    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof(CONSOLE_FONT_INFOEX);
    if (!GetCurrentConsoleFontEx(hConsole, FALSE, &cfi)) {
        return;
    }

    wcscpy_s(cfi.FaceName, LF_FACESIZE, L"Consolas");
    cfi.dwFontSize.X = 12;
    cfi.dwFontSize.Y = 24;
    cfi.FontWeight = FW_NORMAL;

    SetCurrentConsoleFontEx(hConsole, FALSE, &cfi);
}
#else
void console_set_consolas_font() {}
#endif
