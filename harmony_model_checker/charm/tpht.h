
#ifndef TPHT_H
#define TPHT_H

#include <cpuid.h>
#include <stdbool.h>
#include <stdint.h>

#include "global.h"
#include "hashdict.h"

#define FIXED_LEN_TPHT_BIN_SIZE 127
#define FIXED_LEN_TPHT_HASH_MASK 0x80
#define FIXED_LEN_TPHT_IN_BIN_MASK 0x7F

struct tpht_assoc {
  uint8_t next;
  unsigned int len;
  unsigned int val_len;
};

struct fixed_len_tpht {
  unsigned int assoc_len;

  uint64_t hash_seed1;
  uint64_t hash_seed2;
  uint64_t base_tab_size;
  uint64_t bin_num;
  uint8_t tiny_ptr_offset;
  uint8_t entry_byte_length;
  uint16_t bin_byte_length;

  uint8_t *byte_array;
  uint8_t *base_tab;
  uint8_t *bin_cnt_head;
};

// tiny pointer hash table
struct tpht {
  char *whoami;
  unsigned int value_len;
  unsigned int length, count;
  unsigned int old_length, old_count;
  struct dict_worker *workers;
  unsigned int nworkers;
  double growth_threshold;
  unsigned int growth_factor;
  unsigned int invoke_count;  // how many time invoked?
  unsigned int depth_count;   // how deep are we searching in the linked list?
  unsigned int depth_max;
  bool concurrent;
  bool align16;  // entries must be aligned to 16 bytes
  bool autogrow;

  unsigned int max_assoc_len;
  struct fixed_len_tpht *fixed_len_ht_list;
};

void fixed_len_tpht_new(struct fixed_len_tpht *ht, unsigned int assoc_len,
                        unsigned int size, struct allocator *al, bool align16);

struct fixed_len_tpht *get_tpht_of_size(unsigned int size, struct tpht *tpht);

struct tpht *tpht_new(char *whoami, unsigned int value_len,
                      unsigned int initial_size, unsigned int nworkers,
                      bool align16, bool concurrent);

struct tpht_assoc *tpht_find_new(struct tpht *tpht, struct allocator *al,
                                 const void *key, unsigned int keyn,
                                 unsigned int extra, bool *new, uint32_t hash);

bool tpht_overload(struct tpht *tpht);

void tpht_resize(struct tpht *tpht, unsigned int newsize, struct allocator *al, bool align16);

// -ocode/Diners.hco -ocode/Diners.hfa code/Diners.hvm

#endif
