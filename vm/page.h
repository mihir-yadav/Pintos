#ifndef VM_PAGE
#define VM_PAGE

#include "filesys/file.h"
#include "filesys/off_t.h"
#include <hash.h>

enum spte_type
  {
    DATA = 0, /* Only code is swappable. */
    EXECUTABLE = 1, /* Read only executable file. */
    MMAP = 2  /* Files mapped to memory. */
  };

struct spt_entry
  {

    bool writable;
    enum spte_type type;
    off_t ofs;
    struct file *file;
    struct hash_elem el;
    uint32_t page_read_bytes;
    uint32_t page_zero_bytes;
    void *frame;  /* kpage, if not NULL implies installed and loaded (or being loaded). */
    void *user_page;

	};


bool make_spte_executable (struct file *, off_t, uint8_t *, uint32_t, uint32_t, bool);
bool grow_stack (void *);
bool write_to_disk (struct spt_entry *);
struct spt_entry *find_spte_for_addr (void *);
struct spt_entry* make_spte_mmap (struct file *, int, void *);
void remove_hash_table (struct hash *);
void deallot_spte_mmap (struct spt_entry *);
void init_spt (struct hash *);
#endif
