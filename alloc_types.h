#ifndef ALLOC_TYPES_HEADER_GUARD
#define ALLOC_TYPES_HEADER_GUARD

#include <stdint.h>
#include "rbtree.h"

// This file defines all data structures used in the malloc
// implementation, such as run headers and bin metadata.

/***********************
 * Critical Convention *
 ***********************/

// There is only one rb-tree implementation. It consists only of pointers;
// there is no payload. All heap data structures that have rb-tree entried
// (eg small runs) contain an rb-tree node pointer pair struct as the *first*
// item in their definition. Thus, rb-tree node pointers are simply convertible
// into data pointer types. This prevents the need for multiple rb-tree implementations
// at the cost of introducing a type-safety issue. Accordingly, these type
// conversions are done in one place whenenver possible.

/*********************
 * Prototype structs *
 *********************/

struct small_run_hdr;
struct large_run_hdr;
struct arena_bin;
struct arena_chunk_hdr;

/************************
 * Memory and Alignment *
 ************************/

// Borrowed from the original allocator.cpp
// Should not be needed that often, except perhaps sparingly
// once locks are introduced. Other sizes are already aligned.

// All blocks must have a specified minimum alignment.
#define ALIGNMENT 8
// Page size; smallest amount allocated to a run of a size class
#define PAGE_SIZE (4 * 1024) // 4 kB
// Anything larger than this size must be given at least one page
#define MAX_SMALL_SIZE (3840)
// Initial chunk size; heap space given to a new arena when
// there is only one arena
#define INITIAL_CHUNK_SIZE (32 * 4 * 1024) // 128 kB
// Maximum chunk size; maximum size given to an arena
#define FINAL_CHUNK_SIZE (4 * 1024 * 1024) // 4MB
// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// Header offsets, in bytes
#define ARENA_CHUNK_HDR_SIZE (ALIGN(sizeof(arena_chunk_hdr)))
#define ARENA_BIN_SIZE (ALIGN(sizeof(arena_bin)))
#define LARGE_RUN_HDR_SIZE (ALIGN(sizeof(large_run_hdr)))
#define SMALL_RUN_HDR_SIZE (ALIGN(sizeof(small_run_hdr)))

#define NUM_PAGES_IN_CHUNK ((FINAL_CHUNK_SIZE - ARENA_CHUNK_HDR_SIZE) / PAGE_SIZE)

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define ALIGNPAGE(size) (((size) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))
#define ALIGNCHUNK(size) (((size) + (FINAL_CHUNK_SIZE-1)) & ~(FINAL_CHUNK_SIZE-1))

// size_t pointers to object-sized cells in a small run
typedef size_t block;

/****************
 * Size Classes *
 ****************/

// Number of subpage-size size classes
#define NUM_SMALL_CLASSES 28
// This consumes some of our allotted stack space, but that's OK.
// 56 bytes, in fact.
const uint16_t SMALL_CLASS_CONTAINERS[NUM_SMALL_CLASSES] = 
  {8, 
   16, 32, 48, 64, 80, 96, 112, 128,
   192, 256, 320, 384, 448, 512,
   768, 1024, 1280, 1536, 1792, 
   2048, 2304, 2560, 2816, 
   3072, 3328, 3584, 3840}; 

// Get small size class of an allocation request
// Large and HUGE have different handling that
// comes in before this, so checking for those sizes here
// is not handy.
size_t get_small_size_class(size_t real_size) {
  assert(real_size <= MAX_SMALL_SIZE);
  // TODO: Replace with binary search, or something... good. 
  int i;
  // In ascending size order, look for smallest fit
  for(i=0; i<=NUM_SMALL_CLASSES-1; i++) {
    if (real_size <= SMALL_CLASS_CONTAINERS[i]) 
      return SMALL_CLASS_CONTAINERS[i+1];
  }
  return MAX_SMALL_SIZE;
}

/**********************
 * Arena Bin Metadata *
 **********************/

struct arena_bin {
  //LOCK GOES HERE IN FUTURE
  small_run_hdr* current_run; // Pointer to header of current run
  tree_t available_runs; // RB tree of all runs with free space
  size_t object_size; // Size of object stored here, e.g. 192 bytes
  size_t run_length; // Total size of run, e.g. one page
  size_t available_registrations; // How many objects fit in a run of length run_length
};


/****************
 * Arena Chunks *
 ****************/

// For maintenance of a page map, the following may be handy.
// Can't get C++11 typed enum to compile, so you get a stack of 
// defines instead, since the default enum type is too big

#define HEADER 0
#define FREE 1
#define LARGE_RUN_HEADER 2
#define LARGE_RUN_FRAGMENT 3
#define SMALL_RUN_HEADER 4
#define SMALL_RUN_FRAGMENT 5

struct arena_chunk_hdr {
  // Ptr to Arena in multi-Arena case goes here
  // LOCK GOES HERE IN FUTURE
  tree_t clean_page_runs; // For clean *whole pages* for Large allocation
  tree_t dirty_page_runs; // For dirty *whole pages*
  arena_bin bin_headers[NUM_SMALL_CLASSES]; // Store run metadata
  size_t num_pages_allocated; // INITIAL_CHUNK_SIZE <= this <= FINAL_CHUNK_SIZE
                              // ...but don't forget the first page is the header
  uint8_t page_map[(FINAL_CHUNK_SIZE / PAGE_SIZE)]; // Stores state of each page
  // Note above - header data occupies the first free page slot.
};

inline size_t* get_page_location(arena_chunk_hdr* this_hdr, size_t page_no) {
  return (size_t *) ((uint8_t *) this_hdr + (page_no * PAGE_SIZE));
}

/**************
 * Small Runs *
 **************/

// Header entry for a small run, at the top of its page
struct small_run_hdr {
  node_t run_tree_node; // Allows this to be part of a rbtree of runs
  // LOCK GOES HERE IN FUTURE
  arena_bin* parent; // Pointer to our parent bin
  block* free; // Pointer to start block of free list
  block* next; // Pointer to first *never-allocated* block
  size_t free_cells; // How many free cells remain
};

/**************
 * Large Runs *
 **************/

struct large_run_hdr {
  node_t page_tree_node; // For storage in rb tree of whole-page runs
  size_t formal_size; // True size of this allocation.
  size_t num_pages; // How many consecutive pages are assigned to this run
};

#endif /* ALLOC_TYPES_HEADER_GUARD */
