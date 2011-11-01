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

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))


/********************
 * Pages and Chunks *
 ********************/

// Page size; smallest amount allocated to a run of a size class
#define PAGE_SIZE (4 * 1024) // 4 kB
// Initial chunk size; heap space given to a new arena when
// there is only one arena
#define INITIAL_CHUNK_SIZE (32 * 4 * 1024) // 128 kB
// Maximum chunk size; maximum size given to an arena
#define FINAL_CHUNK_SIZE (4 * 1024 * 1024) // 4MB

// size_t pointers to starts of runs of blocks should be named properly.
typedef size_t block;

/**********************
 * Small Size Classes *
 **********************/

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
// We want to do a vaguely-binary search, but these aren't linearly spaced
// There is probably a bit trick to be done here.

// Get size class of an allocation request
size_t get_size_class(size_t real_size) {
  
}


/****************
 * Arena Chunks *
 ****************/

typedef struct arena_chunk_hdr_s {

} arena_chunk_hdr;

/**********************
 * Arena Bin Metadata *
 **********************/

typedef struct arena_bin_s {

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
  block* avail; // Pointer to first *never-allocated* block
  size_t free_cells; // How many free cells remain
} small_run_hdr;

// Size of the header, for offsetting into blocks
// All of these pointers should be 8 bytes anyway,
// but this is harmless.
#define SMALL_RUN_HDR_SIZE ALIGN(sizeof(small_run_hdr))

