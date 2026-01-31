#ifndef XARGS_H
#define XARGS_H

typedef struct {
    char short_opt;
    char* long_opt;
    char* default_value;
    int is_flag;  // 1 = flag option (no value), 0 = option with value
} xArgsCFG;

void xargs_init(xArgsCFG* configs, int count, int argc, char* argv[]);
void xargs_cleanup();

const char* xargs_get(const char* key);
const char* xargs_get_other();

// utils.h
void console_set_consolas_font();

#endif
