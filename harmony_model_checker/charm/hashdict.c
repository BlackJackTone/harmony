#include "head.h"

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>

#include "global.h"
#include "hashdict.h"
#include "thread.h"

#define hash_func meiyan

static inline uint32_t meiyan(const char *key, int count) {
	typedef uint32_t *P;
	uint32_t h = 0x811c9dc5;
	while (count >= 8) {
		h = (h ^ ((((*(P)key) << 5) | ((*(P)key) >> 27)) ^ *(P)(key + 4))) * 0xad3e7;
		count -= 8;
		key += 8;
	}
	#define tmp h = (h ^ *(uint16_t*)key) * 0xad3e7; key += 2;
	if (count & 4) { tmp tmp }
	if (count & 2) { tmp }
	if (count & 1) { h = (h ^ *key) * 0xad3e7; }
	#undef tmp
	return h ^ (h >> 16);
}

static inline struct keynode *keynode_new(struct dict *dict,
        struct allocator *al, char *key, unsigned int len, uint32_t hash){
    unsigned int alen = (len + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
    unsigned int total = sizeof(struct keynode) + alen + dict->value_len;
	struct keynode *k = al == NULL ?  malloc(total) :
                            (*al->alloc)(al->ctx, total, false);
	k->len = len;
	memcpy(k+1, key, len);
	k->next = k->unstable_next = NULL;
	return k;
}

// TODO.  Make iterative rather than recursive
void keynode_delete(struct dict *dict, struct keynode *node) {
	if (node->next) keynode_delete(dict, node->next);
	(*dict->free)(node);
}

struct dict *dict_new(unsigned int value_len, unsigned int initial_size,
        unsigned int nworkers, void *(*m)(size_t size), void (*f)(void *)) {
	struct dict *dict = new_alloc(struct dict);
    dict->value_len = value_len;
	if (initial_size == 0) initial_size = 1024;
	dict->length = initial_size;
	dict->count = 0;
	dict->table = calloc(sizeof(struct dict_bucket), initial_size);
    dict->nlocks = nworkers * 64;        // TODO
    dict->locks = malloc(dict->nlocks * sizeof(mutex_t));
	for (unsigned int i = 0; i < dict->nlocks; i++) {
		mutex_init(&dict->locks[i]);
	}
	dict->growth_threshold = 2;
	dict->growth_factor = 10;
	dict->concurrent = 0;
    dict->workers = calloc(sizeof(struct dict_worker), nworkers);
    dict->nworkers = nworkers;
    for (unsigned int i = 0; i < nworkers; i++) {
        dict->workers[i].unstable = calloc(sizeof(struct keynode *), nworkers);
    }
    dict->malloc = m == NULL ? malloc : m;
    dict->free = f == NULL ? free : f;
	return dict;
}

bool dict_remove(struct dict *dict, const void *key, unsigned int keylen){
    assert(false);
    return false;
}

void dict_delete(struct dict *dict) {
	for (unsigned int i = 0; i < dict->length; i++) {
		if (dict->table[i].stable != NULL)
			keynode_delete(dict, dict->table[i].stable);
		if (dict->table[i].unstable != NULL)
			keynode_delete(dict, dict->table[i].unstable);
	}
	for (unsigned int i = 0; i < dict->nlocks; i++) {
		mutex_destroy(&dict->locks[i]);
    }
	free(dict->table);
	free(dict);
}

static inline void dict_reinsert_when_resizing(struct dict *dict, struct keynode *k) {
    unsigned int n = hash_func((char *) (k+1), k->len) % dict->length;
	struct dict_bucket *db = &dict->table[n];
    k->next = db->stable;
    db->stable = k;
}

static void dict_resize(struct dict *dict, unsigned int newsize) {
	unsigned int o = dict->length;
	struct dict_bucket *old = dict->table;
	dict->table = calloc(sizeof(struct dict_bucket), newsize);
	dict->length = newsize;
	for (unsigned int i = 0; i < o; i++) {
		struct dict_bucket *b = &old[i];
        assert(b->unstable == NULL);
        struct keynode *k = b->stable;
		b->stable = NULL;
		while (k != NULL) {
			struct keynode *next = k->next;
			dict_reinsert_when_resizing(dict, k);
			k = next;
		}
	}
	free(old);
}

// Perhaps the most performance critical function in the entire code base
struct keynode *dict_find(struct dict *dict, struct allocator *al,
                            const void *key, unsigned int keyn, bool *new){
    uint32_t hash = hash_func(key, keyn);
    unsigned int index = hash % dict->length;
    struct dict_bucket *db = &dict->table[index];

    // First see if the item is in the stable list, which does not require
    // a lock
	struct keynode *k = db->stable;
	while (k != NULL) {
		if (k->len == keyn && memcmp((char *) (k+1), key, keyn) == 0) {
            if (new != NULL) {
                *new = false;
            }
			return k;
		}
		k = k->next;
	}

    if (dict->concurrent) {
        mutex_acquire(&dict->locks[index % dict->nlocks]);

        // See if the item is in the unstable list
        k = db->unstable;
        while (k != NULL) {
            if (k->len == keyn && memcmp((char *) (k+1), key, keyn) == 0) {
                mutex_release(&dict->locks[index % dict->nlocks]);
                if (new != NULL) {
                    *new = false;
                }
                return k;
            }
            k = k->next;
        }
    }

    // If not concurrent may have to grow the table now
	if (!dict->concurrent && db->stable == NULL) {
		double f = (double)dict->count / (double)dict->length;
		if (f > dict->growth_threshold) {
			dict_resize(dict, dict->length * dict->growth_factor - 1);
			return dict_find(dict, al, key, keyn, new);
		}
	}

    k = keynode_new(dict, al, (char *) key, keyn, hash);
    if (dict->concurrent) {
        k->next = db->unstable;
        db->unstable = k;
        mutex_release(&dict->locks[index % dict->nlocks]);

        // Keep track of this unstable node in the list for the
        // worker who's going to look at this bucket
        int worker = (hash % dict->length) * dict->nworkers / dict->length;
        k->unstable_next = dict->workers[al->worker].unstable[worker];
        dict->workers[al->worker].unstable[worker] = k;
    }
    else {
        k->next = db->stable;
        db->stable = k;
		dict->count++;
    }

    if (new != NULL) {
        *new = true;
    }
	return k;
}

// Similar to dict_find(), but gets a lock on the bucket
struct keynode *dict_find_lock(struct dict *dict, struct allocator *al,
                            const void *key, unsigned int keyn, bool *new){
    uint32_t hash = hash_func(key, keyn);
    unsigned int index = hash % dict->length;
    struct dict_bucket *db = &dict->table[index];

	if (dict->concurrent) {
		mutex_acquire(&dict->locks[index % dict->nlocks]);
	}

	struct keynode *k = db->stable;
	while (k != NULL) {
		if (k->len == keyn && memcmp((char *) (k+1), key, keyn) == 0) {
            if (new != NULL) {
                *new = false;
            }
			return k;
		}
		k = k->next;
	}

    if (dict->concurrent) {
        // See if the item is in the unstable list
        k = db->unstable;
        while (k != NULL) {
            if (k->len == keyn && memcmp((char *) (k+1), key, keyn) == 0) {
                if (new != NULL) {
                    *new = false;
                }
                return k;
            }
            k = k->next;
        }
    }

    k = keynode_new(dict, al, (char *) key, keyn, hash);
    if (dict->concurrent) {
        k->next = db->unstable;
        db->unstable = k;

        // Keep track of this unstable node in the list for the
        // worker who's going to look at this bucket
        int worker = (hash % dict->length) * dict->nworkers / dict->length;
        k->unstable_next = dict->workers[al->worker].unstable[worker];
        dict->workers[al->worker].unstable[worker] = k;
    }
    else {
        k->next = db->stable;
        db->stable = k;
		dict->count++;
    }

    if (new != NULL) {
        *new = true;
    }
	return k;
}

void dict_insert_release(struct dict *dict, const void *key, unsigned int keylen){
    unsigned int index = hash_func(key, keylen) % dict->length;
    mutex_release(&dict->locks[index % dict->nlocks]);
}

// Returns a pointer to the value
void *dict_insert(struct dict *dict, struct allocator *al,
                            const void *key, unsigned int keyn, bool *new){
    struct keynode *k = dict_find(dict, al, key, keyn, new);
    unsigned int alen = (keyn + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
    return (char *) (k+1) + alen;
}

// Returns a pointer to the value
void *dict_insert_lock(struct dict *dict, struct allocator *al,
                            const void *key, unsigned int keyn, bool *new){
    struct keynode *k = dict_find_lock(dict, al, key, keyn, new);
    unsigned int alen = (keyn + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
    return (char *) (k+1) + alen;
}

void *dict_retrieve(const void *p, unsigned int *psize){
    const struct keynode *k = p;
    if (psize != NULL) {
        *psize = k->len;
    }
    return (char *) (k+1);
}

// This assumes that the value is a pointer.  Returns NULL if there is
// no entry but does not create an entry.
void *dict_lookup(struct dict *dict, const void *key, unsigned int keyn) {
    uint32_t hash = hash_func(key, keyn);
    unsigned int index = hash % dict->length;
    struct dict_bucket *db = &dict->table[index];
	// __builtin_prefetch(db);

    // First look in the stable list, which does not require a lock
	struct keynode *k = db->stable;
	while (k != NULL) {
		if (k->len == keyn && !memcmp((char *) (k+1), key, keyn)) {
            unsigned int alen = (keyn + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
			void **p = (void **) ((char *) (k+1) + alen);
            return *p;
		}
		k = k->next;
	}

    // Look in the unstable list
    if (dict->concurrent) {
        mutex_acquire(&dict->locks[index % dict->nlocks]);
        k = db->unstable;
        while (k != NULL) {
            if (k->len == keyn && !memcmp((char *) (k+1) + dict->value_len, key, keyn)) {
                mutex_release(&dict->locks[index % dict->nlocks]);
                unsigned int alen = (keyn + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
                void **p = (void **) ((char *) (k+1) + alen);
                return *p;
            }
            k = k->next;
        }
        mutex_release(&dict->locks[index % dict->nlocks]);
    }

	return NULL;
}

void dict_iter(struct dict *dict, enumFunc f, void *env) {
	for (unsigned int i = 0; i < dict->length; i++) {
        struct dict_bucket *db = &dict->table[i];
        struct keynode *k = db->stable;
        while (k != NULL) {
            unsigned int alen = (k->len + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
            (*f)(env, (char *) (k+1), k->len, (char *) (k+1) + alen);
            k = k->next;
        }
        if (dict->concurrent) {
            mutex_acquire(&dict->locks[i % dict->nlocks]);
            k = db->unstable;
            while (k != NULL) {
                unsigned int alen = (k->len + DICT_ALIGN - 1) & ~(DICT_ALIGN - 1);
                (*f)(env, (char *) (k+1), k->len, (char *) (k+1) + alen);
                k = k->next;
            }
            mutex_release(&dict->locks[i % dict->nlocks]);
        }
	}
}

// Switch to concurrent mode
void dict_set_concurrent(struct dict *dict) {
    assert(!dict->concurrent);
    dict->concurrent = 1;
}

// When going from concurrent to sequential, need to move over
// the unstable values.
int dict_make_stable(struct dict *dict, unsigned int worker){
    assert(dict->concurrent);
    int n = 0;
	for (unsigned int i = 0; i < dict->nworkers; i++) {
        struct dict_worker *w = &dict->workers[i];
        struct keynode *k;
        while ((k = w->unstable[worker]) != NULL) {
            uint32_t hash = hash_func((char *) (k+1), k->len);
            unsigned int index = hash % dict->length;
            struct dict_bucket *db = &dict->table[index];
            w->unstable[worker] = k->unstable_next;
            k->next = db->stable;
            db->stable = k;
            db->unstable = NULL;
            n++;
        }
    }
    return n;
}

void dict_set_sequential(struct dict *dict, int n) {
    assert(dict->concurrent);
    dict->count += n;

#ifdef notdef
    // check integrity
    struct dict_bucket *db = dict->table;
    unsigned int total = 0;
	for (unsigned int i = 0; i < dict->length; i++, db++) {
        if (db->unstable != NULL) {
            printf("BAD DICT\n");
        }
        for (struct keynode *k = db->stable; k != NULL; k = k->next) {
            total++;
        }
    }
    if (total != dict->count) {
        printf("DICT: bad total\n");
    }
#endif

	double f = (double)dict->count / (double)dict->length;
	if (f > dict->growth_threshold) {
        unsigned int min = dict->length * dict->growth_factor;
        if (min < dict->count) {
            min = dict->count * 2;
        }
		dict_resize(dict, min);
	}
    dict->concurrent = 0;
}
