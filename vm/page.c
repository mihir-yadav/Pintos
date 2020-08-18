#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/page.h"
#include <malloc.h>

static bool lazy_load_file (struct spt_entry *);
static bool lazy_load_mmap (struct spt_entry *);
static bool lazy_load_swap (struct spt_entry *);
static struct spt_entry* create_spte ();
static void deallot_spte_elem (struct hash_elem *, void *);
static void free_spte (struct spt_entry *);


unsigned spt_hash_func (const struct hash_elem *element, void *aux UNUSED)
{
  struct spt_entry *spte = hash_entry (element, struct spt_entry, el);
  return hash_int ((int) spte->user_page);
}

bool spt_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct spt_entry *spte_a = hash_entry (a, struct spt_entry, el);
  struct spt_entry *spte_b = hash_entry (b, struct spt_entry, el);

  return (int) spte_a->user_page < (int) spte_b->user_page;
}

void init_spt (struct hash *supp_page_table)
{
  hash_init (supp_page_table, spt_hash_func, spt_less_func, NULL);
}

struct spt_entry * find_spte_for_addr (void *uvaddr)
{
  void *user_page = pg_round_down (uvaddr);
  struct spt_entry spte;
  spte.user_page = user_page;

  struct hash_elem *e = hash_find (
    &thread_current()->supp_page_table, &spte.el);

  if (e)
    return hash_entry (e, struct spt_entry, el);
  else
    return NULL;
}

static struct spt_entry * create_spte ()
{
  struct spt_entry *spte = (struct spt_entry *) malloc (
    sizeof (struct spt_entry));
  spte->frame = NULL;
  spte->user_page = NULL;
  return spte;
}

struct spt_entry * make_spte_data (void *user_page)
{
  struct spt_entry *spte = create_spte ();
  spte->type = DATA;
  spte->user_page = user_page;
  hash_insert (&((thread_current())->supp_page_table), &spte->el);
  return spte;
}

struct spt_entry * make_spte_mmap (struct file *f, int bytes_to_read, void *user_page)
{
  struct thread *t = thread_current();
  uint32_t page_read_bytes, page_zero_bytes;
  int ofs = 0;
  int i = 0;
  struct spt_entry *first_spte = NULL;
  
  while (bytes_to_read > 0)
  {
    page_read_bytes = bytes_to_read < PGSIZE ? bytes_to_read : PGSIZE;
    page_zero_bytes = PGSIZE - page_read_bytes;

    struct spt_entry *spte = find_spte_for_addr (user_page);
    if (spte != NULL){
      deallot_spte_mmap (first_spte);
      return NULL;
    }
    
    spte = create_spte ();
    spte->type = MMAP;
    spte->user_page = user_page;
    spte->file = f;
    spte->ofs = ofs;
    spte->page_read_bytes = page_read_bytes;
    spte->page_zero_bytes = page_zero_bytes;
    spte->writable = true;

    ofs += page_read_bytes;
    bytes_to_read -= page_read_bytes;
    user_page += PGSIZE;
    
    hash_insert (&(t->supp_page_table), &spte->el);
    if (i == 0)
    {
      first_spte = spte;
      i++;
    }
    
  }
  return first_spte;
}
  

bool make_spte_executable (struct file *file, off_t ofs, uint8_t *user_page,
              uint32_t bytes_to_read, uint32_t bytes_to_null, bool writable) 
{
//  ASSERT ((bytes_to_read + bytes_to_null) % PGSIZE == 0);
  ASSERT (pg_ofs (user_page) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (bytes_to_read > 0 || bytes_to_null > 0) 
    {
      size_t page_read_bytes = bytes_to_read < PGSIZE ? bytes_to_read : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct spt_entry *spte = create_spte ();
      spte->type = EXECUTABLE;
      spte->user_page = user_page;
      spte->page_read_bytes = page_read_bytes;
      spte->page_zero_bytes = page_zero_bytes;
      spte->file = file;
      spte->ofs = ofs;
      spte->writable = writable;
      ofs += page_read_bytes;
      
      bytes_to_read -= page_read_bytes;
      bytes_to_null -= page_zero_bytes;
      user_page += PGSIZE;

      hash_insert (&((thread_current())->supp_page_table), &spte->el);
    }
  return true;
}

static bool lazy_load_executable (struct spt_entry *spte)
{
  void *frame = make_frame (PAL_USER, spte);

  if (frame == NULL)
    return false;

  lock_acquire (&file_lock);
  file_seek (spte->file, spte->ofs);
  int bytes_to_read = file_read (spte->file, frame, spte->page_read_bytes);
  lock_release (&file_lock);
  
  if (bytes_to_read != (int) spte->page_read_bytes)
  {
    deallot_frame (frame);
    return false; 
  }
  memset (frame + spte->page_read_bytes, 0, spte->page_zero_bytes);

  if (!install_page (spte->user_page, frame, spte->writable)) 
  {
    deallot_frame (frame);
    return false; 
  }
  spte->frame = frame;
  return true;
}

static bool lazy_load_mmap (struct spt_entry *spte)
{
  return lazy_load_executable (spte);
}

static bool lazy_load_swap (struct spt_entry *spte)
{
  void *frame = make_frame (PAL_USER | PAL_ZERO, spte);

  if (frame == NULL)
    return false;

  if (install_page (spte->user_page, frame, true))
  {
    spte->frame = frame;
      return true;
  }
  else
    deallot_frame (frame);

  return false;
}

bool lazy_load_page (struct spt_entry *spte)
{
  switch (spte->type){
  case EXECUTABLE:
    return lazy_load_executable (spte);
    break;
  case MMAP:
    return lazy_load_mmap (spte);
    break;
  case DATA:
    return lazy_load_swap (spte);
    break;
  default:
    return false;
  }
}

static void deallot_spte_elem (struct hash_elem *e, void *aux)
{
  struct spt_entry *spte = hash_entry (e, struct spt_entry, el);
  free_spte (spte);
}

void deallot_spte_mmap (struct spt_entry *first_spte)
{
  if (first_spte != NULL)
  {
    int bytes_to_read = file_length (first_spte->file);
    void *user_page = first_spte->user_page;
    struct spt_entry *spte;
    while (bytes_to_read > 0)
    {
      spte = find_spte_for_addr (user_page);
      user_page += PGSIZE;
      bytes_to_read -= spte->page_read_bytes;

      if (spte->file == first_spte->file)
        free_spte (spte);
    }
  }
}

static void free_spte (struct spt_entry *spte)
{
  if (spte != NULL)
  {
    if (spte->frame != NULL)
    {
      if(spte->type == MMAP || (spte->type == EXECUTABLE && spte->writable))
        write_to_disk (spte);

      void *pd = thread_current()->pagedir;
      pagedir_clear_page (pd, spte->user_page);
      deallot_frame (spte->frame);
    }
    
    hash_delete (&thread_current()->supp_page_table,
                   &spte->el);
    free (spte);
  }
}

void remove_hash_table (struct hash *supp_page_table){
  hash_destroy (supp_page_table, deallot_spte_elem);
}

bool grow_stack (void *uaddr)
{
  void *user_page = pg_round_down (uaddr);

  if ((size_t) (PHYS_BASE - uaddr) > MAX_STACK_SIZE)
    return false;
  
  struct spt_entry *spte = make_spte_data (user_page);
  return lazy_load_page (spte);
}

bool write_to_disk (struct spt_entry *spte)
{
  struct thread *t = thread_current ();
  if (pagedir_is_dirty (t->pagedir, spte->user_page))
  {
    lock_acquire (&file_lock);
    off_t written = file_write_at (spte->file, spte->user_page,
                                   spte->page_read_bytes, spte->ofs);
    lock_release (&file_lock);
    if (written != spte->page_read_bytes)
      return false;
  }
  return true;
}
