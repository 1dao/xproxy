#ifndef MAIN_H
#define MAIN_H

// expert for jni
extern int g_running;
extern int xproxy_main(int argc, char *argv[]);
static inline void stop_xproxy() { g_running = 0;}
static inline int is_xproxy_running() { return g_running;}

#endif // MAIN_H
