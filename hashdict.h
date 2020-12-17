// Downloaded from https://github.com/exebook/hashdict.c

#ifndef HASHDICTC
#define HASHDICTC
#include <stdlib.h> /* malloc/calloc */
#include <stdint.h> /* uint32_t */
#include <string.h> /* memcpy/memcmp */

#define HASHDICT_VALUE_TYPE void*
#define KEY_LENGTH_TYPE int

typedef void (*enumFunc)(void *env, const void *key, unsigned int key_size,
                                HASHDICT_VALUE_TYPE value);

struct keynode {
	struct keynode *next;
	char *key;
	KEY_LENGTH_TYPE len;
	HASHDICT_VALUE_TYPE value;
};
		
struct dictionary {
	struct keynode **table;
	int length, count;
	double growth_treshold;
	double growth_factor;
};

struct dictionary* dic_new(int initial_size);
void dic_delete(struct dictionary* dic);
int dic_add(struct dictionary* dic, const void *key, int keyn);
void *dic_lookup(struct dictionary* dic, const void *key, int keyn);
void **dic_insert(struct dictionary *dic, const void *key, int keyn);
void *dic_find(struct dictionary* dic, const void *key, int keyn);
void *dic_retrieve(const void *p, int *psize);
void dic_iter(struct dictionary* dic, enumFunc f, void *user);
#endif
