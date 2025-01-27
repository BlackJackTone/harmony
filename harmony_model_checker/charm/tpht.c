#include "tpht.h"

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "hashdict.h"
#include "value.h"

#define tpht_state_hash tpht_meiyan3
#define tpht_hash1 tpht_meiyan1
#define tpht_hash2 tpht_meiyan2

static inline uint32_t tpht_meiyan1(uintptr_t *s) {
  typedef uint32_t *P;
  unsigned int count = sizeof(s) / 8;
  P key = (P)s;

  uint32_t h = 0x811c9dc5;
  while (count > 0) {
    h = (h ^ ((((*key) << 5) | ((*key) >> 27)) ^ *(key + 1))) * 0xad3e7;
    count--;
    key += 2;
  }
  return h ^ (h >> 16);
}

static inline uint32_t tpht_meiyan2(uintptr_t *s) {
  typedef uint32_t *P;
  unsigned int count = sizeof(s) / 8;
  P key = (P)s;

  uint32_t h = 0x9dc5811c;
  while (count > 0) {
    h = (h ^ ((((*key) << 7) | ((*key) >> 25)) ^ *(key + 1))) * 0xad3e7;
    count--;
    key += 2;
  }
  return h ^ (h >> 16);
}

static inline uint32_t tpht_meiyan3(const struct state *s) {
  typedef uint32_t *P;
  unsigned int count = sizeof(*s) / 8 + s->total;
  P key = (P)s;

  uint32_t h = 0x811c9dc5;
  while (count > 0) {
    h = (h ^ ((((*key) << 5) | ((*key) >> 27)) ^ *(key + 1))) * 0xad3e7;
    count--;
    key += 2;
  }
  return h ^ (h >> 16);
}

void fixed_len_tpht_new(struct fixed_len_tpht *ht, unsigned int assoc_len,
                        unsigned int size, struct allocator *al, bool align16) {
  size = size > FIXED_LEN_TPHT_BIN_SIZE ? size : FIXED_LEN_TPHT_BIN_SIZE;

  ht->assoc_len = assoc_len;

  // Set values directly in the struct
  ht->hash_seed1 = rand() & ((1 << 16) - 1);
  ht->hash_seed2 = 65536 + rand();
  ht->base_tab_size = size * 2;
  ht->bin_num = (size + FIXED_LEN_TPHT_BIN_SIZE - 1) / FIXED_LEN_TPHT_BIN_SIZE;
  ht->tiny_ptr_offset = 0;
  ht->entry_byte_length = ht->assoc_len;
  ht->bin_byte_length = FIXED_LEN_TPHT_BIN_SIZE * ht->entry_byte_length;

  if (al == NULL) {
    posix_memalign(
        (void **)&ht->byte_array, 64,
        ht->bin_num * FIXED_LEN_TPHT_BIN_SIZE * ht->entry_byte_length);
    posix_memalign((void **)&ht->base_tab, 64, ht->base_tab_size);
    posix_memalign((void **)&ht->bin_cnt_head, 64, ht->bin_num << 1);
  } else {
    ht->byte_array = (uint8_t *)(*al->alloc)(
        al->ctx, ht->bin_num * FIXED_LEN_TPHT_BIN_SIZE * ht->entry_byte_length,
        true, align16);
    ht->base_tab =
        (uint8_t *)(*al->alloc)(al->ctx, ht->base_tab_size, true, align16);
    ht->bin_cnt_head =
        (uint8_t *)(*al->alloc)(al->ctx, ht->bin_num << 1, true, align16);
  }

  memset(ht->byte_array, 0,
         ht->bin_num * FIXED_LEN_TPHT_BIN_SIZE * ht->entry_byte_length);
  memset(ht->base_tab, 0, ht->base_tab_size);

  for (uint64_t i = 0, ptr_offset = ht->tiny_ptr_offset; i < ht->bin_num; i++) {
    for (uint8_t j = 0; j < FIXED_LEN_TPHT_BIN_SIZE - 1; j++) {
      ht->byte_array[ptr_offset] = j + 2;
      ptr_offset += ht->entry_byte_length;
    }
    // the last entry in the bin points to null
    ht->byte_array[ptr_offset] = 0;
    ptr_offset += ht->entry_byte_length;

    ht->bin_cnt_head[i << 1] = 0;
    ht->bin_cnt_head[(i << 1) | 1] = 1;
  }
}

static inline struct tpht_assoc *fixed_len_tpht_get_next_assoc(
    struct fixed_len_tpht *ht, uint8_t *next_tp, uintptr_t next_deref_key) {
  uint32_t next_hash = (FIXED_LEN_TPHT_HASH_MASK & *next_tp)
                           ? tpht_hash2(&next_deref_key)
                           : tpht_hash1(&next_deref_key);

  unsigned int next_bin_idx = next_hash % ht->bin_num;

  return (struct tpht_assoc *)(ht->byte_array +
                               next_bin_idx * ht->bin_byte_length +
                               (((*next_tp) & FIXED_LEN_TPHT_IN_BIN_MASK) - 1) *
                                   ht->entry_byte_length);
}

void fixed_len_tpht_insert(struct fixed_len_tpht *ht,
                           struct tpht_assoc *assoc) {
  uint32_t hash = tpht_state_hash((struct state *)(((char *)&assoc[1]) + assoc->val_len));
  unsigned int base_tab_idx = hash % ht->base_tab_size;

  uint8_t *next_tp = &ht->base_tab[base_tab_idx];
  uintptr_t next_deref_key = base_tab_idx;

  while (*next_tp != 0) {
    struct tpht_assoc *cur_assoc =
        fixed_len_tpht_get_next_assoc(ht, next_tp, next_deref_key);
    next_tp = &cur_assoc->next;
    next_deref_key = (uintptr_t)cur_assoc;
  }

  uint32_t bin[2] = {tpht_hash1(&next_deref_key) % ht->bin_num,
                     tpht_hash2(&next_deref_key) % ht->bin_num};

  uint8_t which_bin =
      ht->bin_cnt_head[bin[0] << 1] > ht->bin_cnt_head[bin[1] << 1];

  uint8_t *bin_head = &ht->bin_cnt_head[bin[which_bin] << 1 | 1];

  if (*bin_head == 0) {
    // TODO: rerand
    assert(bin_head);
  }

  *next_tp = *bin_head | (which_bin * FIXED_LEN_TPHT_HASH_MASK);
  struct tpht_assoc *new_assoc =
      (struct tpht_assoc *)(ht->byte_array +
                            bin[which_bin] * ht->bin_byte_length +
                            (*bin_head - 1) * ht->entry_byte_length);

  ht->bin_cnt_head[bin[which_bin] << 1]++;
  *bin_head = new_assoc->next;
  memcpy(new_assoc, assoc, ht->entry_byte_length);
  new_assoc->next = 0;
}

void fixed_len_tpht_resize(struct fixed_len_tpht *ht, uint32_t growth_factor,
                           struct allocator *al, bool align16) {
  struct fixed_len_tpht new_ht;
  fixed_len_tpht_new(&new_ht, ht->assoc_len,
                     ht->bin_num * FIXED_LEN_TPHT_BIN_SIZE * growth_factor, al,
                     align16);

  for (unsigned int i = 0; i < ht->base_tab_size; i++) {
    uint8_t *next_tp = &ht->base_tab[i];
    uintptr_t next_deref_key = i;
    while (*next_tp != 0) {
      struct tpht_assoc *cur_assoc =
          fixed_len_tpht_get_next_assoc(ht, next_tp, next_deref_key);

      fixed_len_tpht_insert(&new_ht, cur_assoc);

      next_tp = &cur_assoc->next;
      next_deref_key = (uintptr_t)cur_assoc;
    }
  }

  if (al == NULL) {
    free(ht->byte_array);
    free(ht->base_tab);
    free(ht->bin_cnt_head);
  } else {
    (*al->free)(al->ctx, ht->byte_array, align16);
    (*al->free)(al->ctx, ht->base_tab, align16);
    (*al->free)(al->ctx, ht->bin_cnt_head, align16);
  }

  *ht = new_ht;
}

struct fixed_len_tpht *get_tpht_of_size(unsigned int size, struct tpht *ht) {
  if (size > ht->max_assoc_len) {
    ht->fixed_len_ht_list = (struct fixed_len_tpht *)realloc(
        ht->fixed_len_ht_list, size * sizeof(struct fixed_len_tpht));
    memset(ht->fixed_len_ht_list + ht->max_assoc_len, 0,
           (size - ht->max_assoc_len) * sizeof(struct fixed_len_tpht));
    ht->max_assoc_len = size;
  }
  return &ht->fixed_len_ht_list[size - 1];
}

struct tpht *tpht_new(char *whoami, unsigned int value_len,
                      unsigned int initial_size, unsigned int nworkers,
                      bool align16, bool concurrent) {
  assert(concurrent == 0);
  struct tpht *ht = new_alloc(struct tpht);
  ht->whoami = whoami;
  ht->value_len = value_len;
  if (initial_size == 0) {
    initial_size = 1024;
  }
  ht->length = ht->old_length = initial_size;
  ht->count = ht->old_count = 0;
  ht->concurrent = concurrent;
  ht->align16 = align16;
  ht->autogrow = true;
  ht->growth_threshold = 2;
  ht->growth_factor = 10;
  ht->invoke_count = 0;
  ht->depth_count = 0;
  ht->depth_max = 0;
  ht->max_assoc_len = 0;
  ht->fixed_len_ht_list = NULL;
  return ht;
}

static inline void tpht_assoc_new(struct tpht *tpht, struct tpht_assoc *k,
                                  char *key, unsigned int len,
                                  unsigned int extra) {
  k->len = len;
  k->val_len = tpht->value_len + extra;
  memcpy((char *)&k[1] + k->val_len, key, len);
}

struct tpht_assoc *tpht_find_new(struct tpht *tpht, struct allocator *al,
                                 const void *key, unsigned int keyn,
                                 unsigned int extra, bool *new, uint32_t hash) {
  unsigned int total =
      sizeof(struct tpht_assoc) + tpht->value_len + extra + keyn;

  struct fixed_len_tpht *ht = get_tpht_of_size(total, tpht);

  if (ht->base_tab == NULL) {
    fixed_len_tpht_new(ht, total, tpht->length, al, tpht->align16);
    // fixed_len_tpht_new(ht, total, tpht->length / tpht->max_assoc_len, al,
    //  tpht->align16);
  }

  unsigned int base_tab_idx =
      tpht_state_hash((struct state *)key) % ht->base_tab_size;

  uint8_t *next_tp = &ht->base_tab[base_tab_idx];
  uintptr_t next_deref_key = base_tab_idx;

  unsigned int depth = 0;

  while (*next_tp != 0) {
    struct tpht_assoc *cur_assoc =
        fixed_len_tpht_get_next_assoc(ht, next_tp, next_deref_key);

    if (cur_assoc->len == keyn &&
        memcmp(key, ((char *)&cur_assoc[1]) + cur_assoc->val_len, keyn) == 0) {
      *new = false;
      return cur_assoc;
    }

    depth++;
    tpht->depth_count++;

    next_tp = &cur_assoc->next;
    next_deref_key = (uintptr_t)cur_assoc;
  }

  *new = true;

  uint32_t bin[2] = {tpht_hash1(&next_deref_key) % ht->bin_num,
                     tpht_hash2(&next_deref_key) % ht->bin_num};

  uint8_t which_bin =
      ht->bin_cnt_head[bin[0] << 1] > ht->bin_cnt_head[bin[1] << 1];

  uint8_t *bin_head = &ht->bin_cnt_head[bin[which_bin] << 1 | 1];

  if (*bin_head == 0) {
    fixed_len_tpht_resize(ht, tpht->growth_factor, al, tpht->align16);
    return tpht_find_new(tpht, al, key, keyn, extra, new, hash);
  }

  *next_tp = *bin_head | (which_bin * FIXED_LEN_TPHT_HASH_MASK);
  struct tpht_assoc *new_assoc =
      (struct tpht_assoc *)(ht->byte_array +
                            bin[which_bin] * ht->bin_byte_length +
                            (*bin_head - 1) * ht->entry_byte_length);

  ht->bin_cnt_head[bin[which_bin] << 1]++;
  *bin_head = new_assoc->next;
  tpht_assoc_new(tpht, new_assoc, (char *)key, keyn, extra);
  new_assoc->next = 0;

  tpht->count++;
  *new = true;
  if (tpht->depth_max < depth) {
    tpht->depth_max = depth;
  }

  return new_assoc;
}

bool tpht_overload(struct tpht *tpht) { return 0; }

void tpht_resize(struct tpht *tpht, unsigned int newsize, struct allocator *al,
                 bool align16) {
  return;
}
