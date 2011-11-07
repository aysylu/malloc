#include<iostream>
#include<cstdlib>
#include<cstring>
#include "allocator_interface.h"
#include "memlib.h"
#include "alloc_types.h"
#ifdef DEBUG
#include "visualizer.h"
#endif
namespace my
{
  /*
   * check - This checks our invariant that the size_t header before every
   * block points to either the beginning of the next block, or the end of the
   * heap.
   */
  int allocator::check()
  {
    char *p;
    char *lo = (char*)mem_heap_lo();
    char *hi = (char*)mem_heap_hi() + 1;
    size_t size = 0;

    p = lo;
    while (lo <= p && p < hi) {
      size = ALIGN(*(size_t*)p + SIZE_T_SIZE);
      p += size;
    }

    if (p != hi) {
      printf("Bad headers did not end at heap_hi!\n");
      printf("heap_lo: %p, heap_hi: %p, size: %lu, p: %p\n", lo, hi, size, p);
      return -1;
    }

    return 0;
  }

  /*
   * init - Initialize the malloc package. Called once before any other
   * calls are made. This sets up the initial arena and creates a chunk.
   */
  int allocator::init()
  {
    // Allocate memory for an arena header and its first chunk
    // Conveniently, this is just under our slackness limit.
    size_t initial_allocation = ARENA_HDR_SIZE + INITIAL_CHUNK_SIZE;
    byte* new_mem = (byte*)mem_sbrk(initial_allocation);
    if (new_mem == NULL) {
      return -1; // Panic! Not out fault!
    }
    
    // Write in the arena header; chunk header written by arena initializer
    arena_hdr* this_arena = (arena_hdr*)mem_heap_lo();

    *this_arena = arena_hdr();
    // Now that it's on the heap, we can finish initialization
    this_arena->finalize();
    this_arena->insert_chunk((node_t*) ((byte*)(mem_heap_lo()) + ARENA_HDR_SIZE));
    // If we had failed, exceptions would have appeared elsewhere.
    return 0;
  }

  /*
   * malloc - Allocate a block by incrementing the brk pointer.
   *     Always allocate a block whose size is a multiple of the alignment.
   */
  void * allocator::malloc(size_t size)
  {
    // Send this size to the lone arena for allocation
#ifdef DEBUG
    // Use arena visualization
    visualize_arena(((arena_hdr*)(mem_heap_lo())));
#endif
    return ((arena_hdr*)(mem_heap_lo()))->malloc(size);
  }

  /*
   * free - Freeing a block does nothing.
   */
  void allocator::free(void *ptr)
  {
    if (ptr == NULL)
      return;
    // Find arena control structure at the bottom of the heap and delegate.
    ((arena_hdr*)(mem_heap_lo()))->free(ptr);
  }

  /*
   * realloc - Implemented simply in terms of malloc and free
   */
  void * allocator::realloc(void *ptr, size_t size)
  {
    void *newptr;
    size_t copy_size;

    /* Allocate a new chunk of memory, and fail if that allocation fails. */
    newptr = malloc(size);
    if (NULL == newptr)
      return NULL;

    /* Get the size of the old block of memory.  Take a peek at malloc(),
       where we stashed this in the SIZE_T_SIZE bytes directly before the
       address we returned.  Now we can back up by that many bytes and read
       the size. */
    copy_size = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);

    /* If the new block is smaller than the old one, we have to stop copying
       early so that we don't write off the end of the new block of memory. */
    if (size < copy_size)
      copy_size = size;

    /* This is a standard library call that performs a simple memory copy. */
    std::memcpy(newptr, ptr, copy_size);

    /* Release the old block. */
    free(ptr);

    /* Return a pointer to the new block. */
    return newptr;
  }

  /* call mem_reset_brk. */
  void allocator::reset_brk()
  {
    mem_reset_brk() ;
  }

  /* call mem_heap_lo */
  void * allocator::heap_lo()
  {
    return mem_heap_lo() ;
  }

  /* call mem_heap_hi */
  void * allocator::heap_hi()
  {
    return mem_heap_hi() ;
  }


};
