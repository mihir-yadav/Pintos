#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"
#include <malloc.h>

struct list frame_table;
struct lock frame_table_lock;


// Allot a frame to the the given page and vv
	
static void * allot_frame (enum palloc_flags flags)
{
  if (flags & PAL_USER == 0)
    return NULL;

  void *frame = palloc_get_page (flags);
  if (frame != NULL)
    return frame;
  else
  {
    return NULL;
  }
}

// Initialize the frame table system
void initialize_frame (void)
{
  list_init (&frame_table);
  lock_init (&frame_table_lock);
}

// Make a new frame with given flags and spte

void * make_frame (enum palloc_flags flags, struct spt_entry *spte)
{
  if (flags & PAL_USER == 0)
    return NULL;

  void *frame = allot_frame (flags);

  if (frame != NULL && spte != NULL){
    record_frame (frame, spte);
    return frame;
  }
  else return NULL;
}

// Record the given frame in the frame table

static void record_frame (void *frame, struct spt_entry *spte) {
  struct frame_table_entry *fte =
    (struct frame_table_entry *) malloc (sizeof (struct frame_table_entry));

  lock_acquire (&frame_table_lock);
  fte->frame = frame;
  fte->spte = spte;
  fte->t = thread_current ();
  list_push_back (&frame_table, &fte->el);
  lock_release (&frame_table_lock);
}


// Remove the frame that was alloted previously.

void deallot_frame (void *frame)
{
  palloc_free_page (frame);
}
