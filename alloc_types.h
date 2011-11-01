#include <stdint.h>
#include "rbtree.h"

// This file defines all data structures used in the malloc
// implementation, such as run headers and bin metadata.

/*********************
 * Prototype structs *
 *********************/

struct arena_bin_hdr_s;
struct arena_bin_s;
struct arena_bhunk_hdr_s;

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



// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define ALIGNPAGE(size) (((size) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))
#define ALIGNCHUNK(size) (((size) + (FINAL_CHUNK_SIZE-1)) & ~(FINAL_CHUNK_SIZE-1))

// size_t pointers to starts of runs of objects should be named properly.
typedef size_t object;

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
  assert(real_size <= MAX_SMALL_SIZE)
  // TODO: Replace with binary search, or something... good. 
  int i;
  // In ascending size order, look for smallest fit
  for(i=0; i<=NUM_SIZE_CLASSES-1; i++) {
    if (real_size <= SMALL_CLASS_CONTAINERS[i]) 
      return SMALL_CLASS_CONTAINERS[i+1];
  }
  return MAX_SMALL_SIZE;
}



/****************
 * Arena Chunks *
 ****************/

// For maintenance of a page map, the following may be handy.
typedef enum page_state_e {FREE, SMALL_RUN_HEAD, SMALL_RUN_FRAGMENT, 
			   LARGE_RUN_HEAD, LARGE_RUN_FRAGMENT} page_state;

typedef struct arena_chunk_hdr_s {
  // Ptr to Arena in multi-Arena case goes here
  


} arena_chunk_hdr;

/**********************
 * Arena Bin Metadata *
 **********************/

typedef struct arena_bin_s {
  //LOCK GOES HERE IN FUTURE
  small_run_hdr* current_run; // Pointer to header of current run
  tree_t available_runs; // RB tree of all runs with free space
  size_t object_size; // Size of object stored here, e.g. 192 bytes
  size_t run_length; // Total size of run, e.g. one page
  size_t available_registrations; // How many objects fit in a run of length run_length
} arena_bin;

/**************
 * Small Runs *
 **************/

// Header entry for a small run, at the top of its page
typedef struct small_run_hdr_s {
  node_t run_tree_node; // Allows this to be part of a rbtree of runs
  // LOCK GOES HERE IN FUTURE
  arena_bin* parent; // Pointer to our parent bin
  block* free; // Pointer to start block of free list
  block* next; // Pointer to first *never-allocated* block
  size_t free_cells; // How many free cells remain
} small_run_hdr;

// Size of the header, for offsetting into blocks
// All of these pointers should be 8 bytes anyway,
// but this is harmless.
#define SMALL_RUN_HDR_SIZE ALIGN(sizeof(small_run_hdr))

