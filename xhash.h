#ifndef __XHASH_H__
#define __XHASH_H__

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

/* ========== Inline Control ========== */
/* Add preprocessor control to allow disabling inlining */
#ifndef XHASH_NO_INLINE
    #define XHASH_INLINE static inline
#else
    #define XHASH_INLINE
#endif

/* Hash key type enumeration */
typedef enum {
    XHASH_KEY_INT,    /* Integer key */
    XHASH_KEY_STR     /* String key */
} xHashKeyType;

/* Hash node structure */
typedef struct xHashNode {
    union {
        long long int_key;      /* Integer key */
        char *str_key;          /* String key */
    } key;
    xHashKeyType key_type;
    void *value;               /* Value pointer */
    struct xHashNode *next;     /* Chaining for conflict resolution */
    int next_idx;               /* ID of next node */
} xhashNode;

/* Hash table structure */
typedef struct {
    xhashNode **buckets;        /* Bucket array */
    size_t size;               /* Hash table size */
    size_t count;              /* Number of elements */
    int    head_idx;           /* ID of head node */
} xhash;

/* Default hash table size */
#define XHASH_DEFAULT_SIZE 64

/* ========== Hash Table Operations ========== */

/**
 * Create a hash table
 * @param size Hash table size (number of buckets), 0 means use default value
 * @return Hash table pointer, returns NULL on failure
 */
XHASH_INLINE xhash* xhash_create(size_t size) {
    if (size == 0) {
        size = XHASH_DEFAULT_SIZE;
    }

    xhash *hash = (xhash*)malloc(sizeof(xhash));
    if (!hash) {
        return NULL;
    }

    hash->buckets = (xhashNode**)calloc(size, sizeof(xhashNode*));
    if (!hash->buckets) {
        free(hash);
        return NULL;
    }

    hash->size = size;
    hash->count = 0;
    hash->head_idx = -1;
    return hash;
}

/**
 * Destroy hash table (free all resources)
 * @param hash Hash table pointer
 * @param free_value Whether to free value (true=free, false=don't free)
 */
XHASH_INLINE void xhash_destroy(xhash *hash, bool free_value) {
    if (!hash) {
        return;
    }

    for (size_t i = 0; i < hash->size; i++) {
        xhashNode *node = hash->buckets[i];
        while (node) {
            xhashNode *next = node->next;

            if (node->key_type == XHASH_KEY_STR && node->key.str_key) {
                free(node->key.str_key);
            }

            if (free_value && node->value) {
                free(node->value);
            }

            free(node);
            node = next;
        }
        hash->buckets[i] = NULL;
    }

    free(hash->buckets);
    hash->buckets = NULL;
    free(hash);
}

/**
 * Hash function - integer key
 */
XHASH_INLINE unsigned int xhash_int_func(long long key, size_t size) {
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;
    return (unsigned int)((unsigned long long)key % size);
}

/**
 * Hash function - string key (same algorithm as xargs.c)
 */
XHASH_INLINE unsigned int xhash_str_func(const char *str, size_t size) {
    unsigned int h = 0;
    while (*str) {
        h = h * 31 + *str++;
    }
    return h % size;
}

static inline int find_prev_idx(xhash *hash, int target_idx) {
    int current_idx = hash->head_idx;
    int prev_idx = -1;

    while (current_idx != -1 && current_idx != target_idx) {
        xhashNode *node = hash->buckets[current_idx];
        if (!node) break;  // Safety check

        prev_idx = current_idx;
        current_idx = node->next_idx;
    }
    return current_idx == target_idx ? prev_idx : -1;
}

/**
 * Set integer key value
 * @param hash Hash table pointer
 * @param key Integer key
 * @param value Value pointer
 * @return Returns true on success, false on failure
 */
XHASH_INLINE bool xhash_set_int(xhash *hash, long long key, void *value) {
    if (!hash) return false;

    unsigned int idx = xhash_int_func(key, hash->size);
    xhashNode *node = hash->buckets[idx];

    /* Check if already exists, update if found */
    while (node) {
        if (node->key_type == XHASH_KEY_INT && node->key.int_key == key) {
            node->value = value;
            return true;
        }
        node = node->next;
    }

    /* Create new node */
    node = (xhashNode*)malloc(sizeof(xhashNode));
    if (!node) {
        return false;
    }

    node->key_type = XHASH_KEY_INT;
    node->key.int_key = key;
    node->value = value;
    node->next = hash->buckets[idx];

    // If this is the first node in the bucket, update the list
    if (!hash->buckets[idx]) {
        node->next_idx = hash->head_idx;
        hash->head_idx = idx;
    } else {
        node->next_idx = hash->buckets[idx]->next_idx;  // Inherit next_idx from original head node
    }

    hash->buckets[idx] = node;
    hash->count++;

    return true;
}

/**
 * Get integer key value
 * @param hash Hash table pointer
 * @param key Integer key
 * @return Value pointer, returns NULL if not found
 */
XHASH_INLINE void* xhash_get_int(xhash *hash, long long key) {
    if (!hash) {
        return NULL;
    }

    unsigned int idx = xhash_int_func(key, hash->size);
    xhashNode *node = hash->buckets[idx];

    while (node) {
        if (node->key_type == XHASH_KEY_INT && node->key.int_key == key) {
            return node->value;
        }
        node = node->next;
    }

    return NULL;
}

/**
 * Remove integer key
 * @param hash Hash table pointer
 * @param key Integer key
 * @param free_value Whether to free value
 * @return Returns true on success, false if not found
 */
XHASH_INLINE bool xhash_remove_int(xhash *hash, long long key, bool free_value) {
    if (!hash) return false;

    unsigned int idx = xhash_int_func(key, hash->size);
    xhashNode **pp = &hash->buckets[idx];
    bool removed_was_head = false;

    while (*pp) {
        if ((*pp)->key_type == XHASH_KEY_INT && (*pp)->key.int_key == key) {
            xhashNode *to_remove = *pp;
            removed_was_head = (to_remove == hash->buckets[idx]);
            *pp = (*pp)->next;  // Remove from bucket's linked list

            if (free_value && to_remove->value)
                free(to_remove->value);

            // If bucket becomes empty, need to update next_idx list
            if (hash->buckets[idx] == NULL) {
                // Find previous bucket
                int prev_idx = find_prev_idx(hash, idx);

                if (prev_idx != -1 && hash->buckets[prev_idx]) {
                    // Point previous bucket's next_idx to current bucket's next_idx (skip current bucket)
                    hash->buckets[prev_idx]->next_idx = to_remove->next_idx;
                } else if (hash->head_idx == (int)idx) {
                    // If deleting head node, update head_idx
                    hash->head_idx = to_remove->next_idx;
                }
            } else {
                // If bucket still has other nodes, new head node inherits deleted node's next_idx
                if (removed_was_head)
                    hash->buckets[idx]->next_idx = to_remove->next_idx;
            }

            free(to_remove);
            hash->count--;
            return true;
        }
        pp = &(*pp)->next;
    }

    return false;
}

/**
 * Set string key value
 * @param hash Hash table pointer
 * @param key String key
 * @param value Value pointer
 * @return Returns true on success, false on failure
 */
XHASH_INLINE bool xhash_set_str(xhash *hash, const char *key, void *value) {
    if (!hash || !key)
        return false;

    unsigned int idx = xhash_str_func(key, hash->size);
    xhashNode *node = hash->buckets[idx];

    /* Check if already exists, update if found */
    while (node) {
        if (node->key_type == XHASH_KEY_STR &&
            node->key.str_key && strcmp(node->key.str_key, key) == 0) {
            node->value = value;
            return true;
        }
        node = node->next;
    }

    /* Create new node */
    node = (xhashNode*)malloc(sizeof(xhashNode));
    if (!node)
        return false;
    node->key_type = XHASH_KEY_STR;
    node->key.str_key = strdup(key);
    if (!node->key.str_key) {
        free(node);
        return false;
    }

    node->value = value;
    node->next = hash->buckets[idx];

    // If this is the first node in the bucket, update the list
    if (!hash->buckets[idx]) {
        node->next_idx = hash->head_idx;
        hash->head_idx = idx;
    } else {
        node->next_idx = hash->buckets[idx]->next_idx;  // Inherit next_idx from original head node
    }

    hash->buckets[idx] = node;
    hash->count++;

    return true;
}

/**
 * Get string key value
 * @param hash Hash table pointer
 * @param key String key
 * @return Value pointer, returns NULL if not found
 */
XHASH_INLINE void* xhash_get_str(xhash *hash, const char *key) {
    if (!hash || !key) {
        return NULL;
    }

    unsigned int idx = xhash_str_func(key, hash->size);
    xhashNode *node = hash->buckets[idx];

    while (node) {
        if (node->key_type == XHASH_KEY_STR &&
            node->key.str_key && strcmp(node->key.str_key, key) == 0) {
            return node->value;
        }
        node = node->next;
    }

    return NULL;
}

/**
 * Remove string key
 * @param hash Hash table pointer
 * @param key String key
 * @param free_value Whether to free value
 * @return Returns true on success, false if not found
 */
XHASH_INLINE bool xhash_remove_str(xhash *hash, const char *key, bool free_value) {
    if (!hash || !key)
        return false;

    unsigned int idx = xhash_str_func(key, hash->size);
    xhashNode **pp = &hash->buckets[idx];
    bool removed_was_head = false;

    while (*pp) {
        if ((*pp)->key_type == XHASH_KEY_STR &&
            (*pp)->key.str_key && strcmp((*pp)->key.str_key, key) == 0) {
            xhashNode *to_remove = *pp;
            removed_was_head = (to_remove == hash->buckets[idx]);
            *pp = (*pp)->next;  // Remove from bucket's linked list

            if (to_remove->key.str_key) {
                free(to_remove->key.str_key);
            }

            if (free_value && to_remove->value) {
                free(to_remove->value);
            }

            // If bucket becomes empty, need to update next_idx list
            if (hash->buckets[idx] == NULL) {
                // Find previous bucket
                int prev_idx = find_prev_idx(hash, idx);

                if (prev_idx != -1 && hash->buckets[prev_idx]) {
                    // Point previous bucket's next_idx to current bucket's next_idx (skip current bucket)
                    hash->buckets[prev_idx]->next_idx = to_remove->next_idx;
                } else if (hash->head_idx == (int)idx) {
                    // If deleting head node, update head_idx
                    if (removed_was_head)
                        hash->head_idx = to_remove->next_idx;
                }
            } else {
                // If bucket still has other nodes, new head node inherits deleted node's next_idx
                hash->buckets[idx]->next_idx = to_remove->next_idx;
            }

            free(to_remove);
            hash->count--;
            return true;
        }
        pp = &(*pp)->next;
    }

    return false;
}

/**
 * Get hash table element count
 * @param hash Hash Hash table pointer
 * @return Number of elements
 */
XHASH_INLINE size_t xhash_size(xhash *hash) {
    return hash ? hash->count : 0;
}

/**
 * Traverse hash table
 * @param hash Hash table pointer
 * @param callback Callback function: bool (*callback)(xhashNode *node, void *ctx)
 * @param ctx Context pointer
 */
XHASH_INLINE void xhash_foreach(xhash *hash, bool (*callback)(xhashNode *node, void *ctx), void *ctx) {
    if (!hash || !callback)
        return;

    int current_idx = hash->head_idx;
    int processed_count = 0;
    int ncount = (int)hash->count;
    xhashNode *node, *next;
    while (current_idx != -1 && processed_count < ncount) {
        node = hash->buckets[current_idx];

        // Move to next bucket
        current_idx = node ? node->next_idx : -1;

        // Traverse all nodes in current bucket
        while (node && processed_count < ncount) {
            next = node->next;
            if (!callback(node, ctx)) {
                return;
            }
            node = next;
            processed_count++;
        }
    }
    if(ncount!=processed_count){
        fprintf(stderr, "hash set invalid :%d-%d", ncount, processed_count);
        fprintf(stderr, "hash set invalid :%d-%d", ncount, processed_count);
        fprintf(stderr, "hash set invalid :%d-%d", ncount, processed_count);
    }
}

/**
 * Resize hash table (expand or shrink)
 * @param hash Hash table pointer
 * @param new_size New size
 * @return Returns true on success, false on failure
 */
XHASH_INLINE bool xhash_resize(xhash *hash, size_t new_size) {
    if (!hash || new_size == 0 || new_size == hash->size) {
        return false;
    }

    xhashNode **new_buckets = (xhashNode**)calloc(new_size, sizeof(xhashNode*));
    if (!new_buckets) {
        return false;
    }

    /* Rehash all nodes */
    for (size_t i = 0; i < hash->size; i++) {
        xhashNode *node = hash->buckets[i];
        while (node) {
            xhashNode *next = node->next;

            /* Calculate new bucket index */
            unsigned int new_idx;
            if (node->key_type == XHASH_KEY_INT) {
                new_idx = xhash_int_func(node->key.int_key, new_size);
            } else {
                new_idx = xhash_str_func(node->key.str_key, new_size);
            }

            /* Insert into new bucket */
            node->next = new_buckets[new_idx];
            new_buckets[new_idx] = node;

            node = next;
        }
    }

    free(hash->buckets);
    hash->buckets = new_buckets;
    hash->size = new_size;

    /* Rebuild head_idx/next_idx */
    hash->head_idx = -1;
    for (int i = (int)hash->size - 1; i >= 0; i--) {
        if (hash->buckets[i]) {
            hash->buckets[i]->next_idx = hash->head_idx;
            hash->head_idx = i;
        }
    }
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* __XHASH_H__ */
