#ifndef __XHASH_H__
#define __XHASH_H__

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========== Inline Control ========== */
#ifndef XHASH_NO_INLINE
    #define XHASH_INLINE static inline
#else
    #define XHASH_INLINE
#endif

/* ========== Allocator Macros ========== */
/*
 * Override before including xhash.h to redirect to minialloc:
 *
 *   #define XHASH_MALLOC(sz)  mal_alloc(&g_allocator, (sz))
 *   #define XHASH_FREE(p)     mal_dealloc(&g_allocator, (p))
 *   #define XHASH_STRDUP(s)   xhash_strdup_impl(s)
 *
 * XHASH_STRDUP helper when using minialloc (avoids depending on strdup):
 *
 *   static inline char* xhash_strdup_impl(const char *s) {
 *       size_t n = strlen(s) + 1;
 *       char  *p = (char*)XHASH_MALLOC(n);
 *       if (p) memcpy(p, s, n);
 *       return p;
 *   }
 */
#ifndef XHASH_MALLOC
    #define XHASH_MALLOC(sz)  malloc(sz)
    #define XHASH_FREE(p)     free(p)
#endif
#ifndef XHASH_STRDUP
    /* strdup needs _POSIX_C_SOURCE on some platforms */
    #if !defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)
        #define _POSIX_C_SOURCE 200809L
    #endif
    #define XHASH_STRDUP(s)   strdup(s)
#endif

/* ========== Key Type ========== */
typedef enum { XHASH_KEY_INT, XHASH_KEY_STR } xhashKeyType;

/* ========== Unified Key ========== */
/*
 * Used in foreach callbacks so callers get a single, strongly-typed key.
 * On 64-bit platforms long long and char* are both 8 bytes → zero overhead.
 */
typedef union {
    long long   i;   /* valid when table was created with XHASH_KEY_INT */
    const char *s;   /* valid when table was created with XHASH_KEY_STR */
} xhashKey;

/* ========== Node ========== */
/*
 * Single node type for both int and str tables.
 * key.i / key.s is selected by the owning xhash's key_type.
 * key.s is owned memory, allocated via XHASH_STRDUP.
 *
 * sizeof(xhashNode) == 24 on 64-bit → minialloc pool_5 (32-byte chunks).
 * All nodes in a table hit the same pool regardless of key type.
 */
typedef struct xhashNode {
    union {
        long long  i;
        char      *s;
    } key;
    void             *value;
    struct xhashNode *next;   /* next node in the same bucket (chaining) */
} xhashNode;

/* ========== Active Bucket Index Tracker ========== */
/*
 * Keeps a compact list of non-empty bucket indices so foreach is
 * O(count) instead of O(size).
 *
 *   indices[0..count-1]  — non-empty bucket indices, unordered
 *   pos[bucket_idx]      — position in indices[], or -1 if empty
 *
 * add / remove are O(1) via swap-with-last.
 */
typedef struct {
    size_t *indices;
    int    *pos;
    size_t  count;
} xhashActive;

XHASH_INLINE bool xhash_active_init(xhashActive *a, size_t size) {
    a->indices = (size_t*)XHASH_MALLOC(size * sizeof(size_t));
    if (!a->indices) return false;
    a->pos = (int*)XHASH_MALLOC(size * sizeof(int));
    if (!a->pos) { XHASH_FREE(a->indices); a->indices = NULL; return false; }
    for (size_t i = 0; i < size; i++) a->pos[i] = -1;
    a->count = 0;
    return true;
}

XHASH_INLINE void xhash_active_free(xhashActive *a) {
    XHASH_FREE(a->indices); a->indices = NULL;
    XHASH_FREE(a->pos);     a->pos     = NULL;
    a->count = 0;
}

XHASH_INLINE void xhash_active_add(xhashActive *a, size_t idx) {
    a->pos[idx]          = (int)a->count;
    a->indices[a->count] = idx;
    a->count++;
}

XHASH_INLINE void xhash_active_remove(xhashActive *a, size_t idx) {
    int    p    = a->pos[idx];
    size_t last = a->indices[a->count - 1];
    a->indices[p] = last;
    a->pos[last]  = p;
    a->pos[idx]   = -1;
    a->count--;
}

/* ========== Hash Table ========== */

typedef struct {
    xhashNode   **buckets;   /* flat array of bucket heads, length = size */
    xhashKeyType  key_type;
    size_t        size;
    size_t        count;
    xhashActive   active;
} xhash;

/* Foreach callback — key.i or key.s valid depending on table's key_type */
typedef bool (*xhashForeachCb)(xhashKey key, void *value, void *ctx);

#define XHASH_DEFAULT_SIZE 64

/* ========== Hash Functions ========== */

XHASH_INLINE unsigned int xhash_int_func(long long key, size_t size) {
    unsigned long long k = (unsigned long long)key;
    k ^= k >> 33; k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33; k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return (unsigned int)(k % size);
}

XHASH_INLINE unsigned int xhash_str_func(const char *s, size_t size) {
    unsigned int h = 0;
    while (*s) h = h * 31 + (unsigned char)*s++;
    return h % size;
}

/* ========== Lifecycle ========== */

XHASH_INLINE xhash* xhash_create(size_t size, xhashKeyType type) {
    if (size == 0) size = XHASH_DEFAULT_SIZE;

    xhash *h = (xhash*)XHASH_MALLOC(sizeof(xhash));
    if (!h) return NULL;

    h->buckets = (xhashNode**)XHASH_MALLOC(size * sizeof(xhashNode*));
    if (!h->buckets) { XHASH_FREE(h); return NULL; }
    memset(h->buckets, 0, size * sizeof(xhashNode*));

    if (!xhash_active_init(&h->active, size)) {
        XHASH_FREE(h->buckets);
        XHASH_FREE(h);
        return NULL;
    }

    h->key_type = type;
    h->size     = size;
    h->count    = 0;
    return h;
}

XHASH_INLINE void xhash_destroy(xhash *h, bool free_value) {
    if (!h) return;

    for (size_t i = 0; i < h->active.count; i++) {
        xhashNode *n = h->buckets[h->active.indices[i]];
        while (n) {
            xhashNode *next = n->next;
            if (h->key_type == XHASH_KEY_STR) XHASH_FREE(n->key.s);
            if (free_value && n->value)        XHASH_FREE(n->value);
            XHASH_FREE(n);
            n = next;
        }
    }

    XHASH_FREE(h->buckets);
    xhash_active_free(&h->active);
    XHASH_FREE(h);
}

/* ========== Integer Key Operations ========== */

XHASH_INLINE bool xhash_set_int(xhash *h, long long key, void *value) {
    assert(h && h->key_type == XHASH_KEY_INT);
    if (!h) return false;

    unsigned int idx = xhash_int_func(key, h->size);
    for (xhashNode *n = h->buckets[idx]; n; n = n->next) {
        if (n->key.i == key) { n->value = value; return true; }
    }

    xhashNode *n = (xhashNode*)XHASH_MALLOC(sizeof(xhashNode));
    if (!n) return false;
    n->key.i = key;
    n->value = value;
    n->next  = h->buckets[idx];
    if (!h->buckets[idx]) xhash_active_add(&h->active, idx);
    h->buckets[idx] = n;
    h->count++;
    return true;
}

XHASH_INLINE void* xhash_get_int(xhash *h, long long key) {
    assert(h && h->key_type == XHASH_KEY_INT);
    if (!h) return NULL;

    unsigned int idx = xhash_int_func(key, h->size);
    for (xhashNode *n = h->buckets[idx]; n; n = n->next)
        if (n->key.i == key) return n->value;
    return NULL;
}

XHASH_INLINE bool xhash_remove_int(xhash *h, long long key, bool free_value) {
    assert(h && h->key_type == XHASH_KEY_INT);
    if (!h) return false;

    unsigned int idx = xhash_int_func(key, h->size);
    xhashNode **pp = &h->buckets[idx];
    while (*pp) {
        if ((*pp)->key.i == key) {
            xhashNode *del = *pp;
            *pp = del->next;
            if (free_value && del->value) XHASH_FREE(del->value);
            XHASH_FREE(del);
            if (!h->buckets[idx]) xhash_active_remove(&h->active, idx);
            h->count--;
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}

/* ========== String Key Operations ========== */

XHASH_INLINE bool xhash_set_str(xhash *h, const char *key, void *value) {
    assert(h && h->key_type == XHASH_KEY_STR);
    if (!h || !key) return false;

    unsigned int idx = xhash_str_func(key, h->size);
    for (xhashNode *n = h->buckets[idx]; n; n = n->next) {
        if (strcmp(n->key.s, key) == 0) { n->value = value; return true; }
    }

    xhashNode *n = (xhashNode*)XHASH_MALLOC(sizeof(xhashNode));
    if (!n) return false;
    n->key.s = XHASH_STRDUP(key);
    if (!n->key.s) { XHASH_FREE(n); return false; }
    n->value = value;
    n->next  = h->buckets[idx];
    if (!h->buckets[idx]) xhash_active_add(&h->active, idx);
    h->buckets[idx] = n;
    h->count++;
    return true;
}

XHASH_INLINE void* xhash_get_str(xhash *h, const char *key) {
    assert(h && h->key_type == XHASH_KEY_STR);
    if (!h || !key) return NULL;

    unsigned int idx = xhash_str_func(key, h->size);
    for (xhashNode *n = h->buckets[idx]; n; n = n->next)
        if (strcmp(n->key.s, key) == 0) return n->value;
    return NULL;
}

XHASH_INLINE bool xhash_remove_str(xhash *h, const char *key, bool free_value) {
    assert(h && h->key_type == XHASH_KEY_STR);
    if (!h || !key) return false;

    unsigned int idx = xhash_str_func(key, h->size);
    xhashNode **pp = &h->buckets[idx];
    while (*pp) {
        if (strcmp((*pp)->key.s, key) == 0) {
            xhashNode *del = *pp;
            *pp = del->next;
            XHASH_FREE(del->key.s);
            if (free_value && del->value) XHASH_FREE(del->value);
            XHASH_FREE(del);
            if (!h->buckets[idx]) xhash_active_remove(&h->active, idx);
            h->count--;
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}

/* ========== Query ========== */

XHASH_INLINE size_t xhash_size(const xhash *h) {
    return h ? h->count : 0;
}

/* ========== Foreach ========== */
/*
 * Single callback type for both int and str tables.
 * Check h->key_type inside the callback to know which union member to read,
 * or just write separate callbacks that always access the correct member.
 *
 * Visits only non-empty buckets — O(count), not O(size).
 * Return false from cb to stop early.
 * Do not modify the table inside cb.
 */
XHASH_INLINE bool xhash_foreach(xhash *h, xhashForeachCb cb, void *ctx) {
    if (!h || !cb) return false;

    if (h->key_type == XHASH_KEY_INT) {
        for (size_t i = 0; i < h->active.count; i++) {
            xhashNode *n = h->buckets[h->active.indices[i]];
            while (n) {
                xhashNode *next = n->next;
                if (!cb((xhashKey){ .i = n->key.i }, n->value, ctx)) return false;
                n = next;
            }
        }
    } else {
        for (size_t i = 0; i < h->active.count; i++) {
            xhashNode *n = h->buckets[h->active.indices[i]];
            while (n) {
                xhashNode *next = n->next;
                if (!cb((xhashKey){ .s = n->key.s }, n->value, ctx)) return false;
                n = next;
            }
        }
    }
    return true;
}

/* ========== Resize ========== */
/*
 * Rehashes all nodes into a new bucket array.
 * Nodes are reused in place — no alloc/free of node memory during resize.
 */
XHASH_INLINE bool xhash_resize(xhash *h, size_t new_size) {
    if (!h || new_size == 0 || new_size == h->size) return false;

    xhashNode **nb = (xhashNode**)XHASH_MALLOC(new_size * sizeof(xhashNode*));
    if (!nb) return false;
    memset(nb, 0, new_size * sizeof(xhashNode*));

    for (size_t i = 0; i < h->active.count; i++) {
        xhashNode *n = h->buckets[h->active.indices[i]];
        while (n) {
            xhashNode *next = n->next;
            unsigned int ni = (h->key_type == XHASH_KEY_INT)
                ? xhash_int_func(n->key.i, new_size)
                : xhash_str_func(n->key.s, new_size);
            n->next = nb[ni];
            nb[ni]  = n;
            n = next;
        }
    }

    XHASH_FREE(h->buckets);
    h->buckets = nb;
    xhash_active_free(&h->active);
    h->size = new_size;

    if (!xhash_active_init(&h->active, new_size)) return false;
    for (size_t i = 0; i < new_size; i++)
        if (h->buckets[i]) xhash_active_add(&h->active, i);

    return true;
}

/* ========== Unified C11 _Generic API ========== */
/*
 * xhash_set / xhash_get / xhash_remove dispatch to the typed function
 * based on the key argument type at compile time.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L

#define xhash_set(h, key, value)    \
    _Generic((key),                 \
        long long:    xhash_set_int,   \
        int:          xhash_set_int,   \
        char *:       xhash_set_str,   \
        const char *: xhash_set_str    \
    )(h, key, value)

#define xhash_get(h, key)           \
    _Generic((key),                 \
        long long:    xhash_get_int,   \
        int:          xhash_get_int,   \
        char *:       xhash_get_str,   \
        const char *: xhash_get_str    \
    )(h, key)

#define xhash_remove(h, key, fv)        \
    _Generic((key),                     \
        long long:    xhash_remove_int, \
        int:          xhash_remove_int, \
        char *:       xhash_remove_str, \
        const char *: xhash_remove_str  \
    )(h, key, fv)

#endif /* C11 */

#ifdef __cplusplus
}
#endif

#endif /* __XHASH_H__ */
