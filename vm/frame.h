#ifndef VM_FRAME
#define VM_FRAME

#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/page.h"
#include <list.h>

struct frame_table_entry
{
  struct list_elem el;
  struct spt_entry *spte;
  struct thread *t;
  void *frame;
};

static void record_frame (void *, struct spt_entry *);
void *make_frame (enum palloc_flags, struct spt_entry *);
void deallot_frame (void *);
void initialize_frame (void);
#endif
