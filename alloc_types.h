#ifndef ALLOC_TYPES_HEADER_GUARD
#define ALLOC_TYPES_HEADER_GUARD

#include <stdint.h>
#include <string.h> // contains memset
#include "rbtree.h"
#include "memlib.h" // Single-threaded case only - grants access to sbrk

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

// Trees cannot be finalized with tree_new until the constructed object has been
// written to the heap. Take care.

/*********************
 * Prototype structs *
 *********************/

struct arena_hdr;
struct arena_chunk_hdr;
struct arena_bin;
struct large_run_hdr;
struct small_run_hdr;
struct huge_run_hdr;

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
// Initial chunk size; heap space given to a new arena when
// there is only one arena. Note: We have a slackness of 10 pages.
// We therefore assign an initial size just under the slackness.
// Constraint: Initial chunk size MUST BE FINAL_CHUNK_SIZE / 2^n
#define INITIAL_CHUNK_SIZE (8 * 4 * 1024) // 32 kB
#define INITIAL_CHUNK_PAGES (INITIAL_CHUNK_SIZE / PAGE_SIZE)
// Maximum chunk size; maximum size given to an arena
#define FINAL_CHUNK_SIZE (1 * 1024 * 1024) // 1MB
#define FINAL_CHUNK_PAGES (FINAL_CHUNK_SIZE / PAGE_SIZE)
// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// Anything larger than this size must be given at least one page
#define MAX_SMALL_SIZE (3840)
// Anything larger than this must be given at least one chunk
#define MAX_LARGE_SIZE (FINAL_CHUNK_SIZE - PAGE_SIZE) // Note - one page always allocated to header
// Anything larger than this must be given at least *two* chunks
#define MAX_SINGLE_CHUNK (FINAL_CHUNK_SIZE - HUGE_RUN_HDR_SIZE)

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define ALIGNPAGE(size) (((size) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))
#define ALIGNCHUNK(size) (((size) + (FINAL_CHUNK_SIZE-1)) & ~(FINAL_CHUNK_SIZE-1))

// Header offsets, in bytes
#define ARENA_HDR_SIZE (ALIGN(sizeof(arena_hdr)))
#define ARENA_CHUNK_HDR_SIZE (ALIGN(sizeof(arena_chunk_hdr)))
#define ARENA_BIN_SIZE (ALIGN(sizeof(arena_bin)))
#define SMALL_RUN_HDR_SIZE (ALIGN(sizeof(small_run_hdr)))
#define LARGE_RUN_HDR_SIZE (ALIGN(sizeof(large_run_hdr)))
#define HUGE_RUN_HDR_SIZE (ALIGN(sizeof(huge_run_hdr)))

#define NUM_PAGES_IN_CHUNK ((FINAL_CHUNK_SIZE - ARENA_CHUNK_HDR_SIZE) / PAGE_SIZE)

// All our pointers need to operate on byte-level math - let's make that a thing
typedef uint8_t byte;

/****************
 * Size Classes *
 ****************/

// Number of subpage-size size classes
#define NUM_SMALL_CLASSES 28
// This consumes some of our allotted stack space, but that's OK.
// 56 bytes, in fact.
const uint16_t SMALL_CLASS_SIZES[NUM_SMALL_CLASSES] = 
  {8, 
   16, 32, 48, 64, 80, 96, 112, 128,
   192, 256, 320, 384, 448, 512,
   768, 1024, 1280, 1536, 1792, 
   2048, 2304, 2560, 2816, 
   3072, 3328, 3584, 3840}; 

/**********************
 * Arena Bin Metadata *
 **********************/

// Defined first because so many things care what size it is.
// Other structures are defined in descending size order.

struct arena_bin {
  //LOCK GOES HERE IN FUTURE
  arena_hdr* parent;
  small_run_hdr* current_run; // Pointer to header of current run
  tree_t available_runs; // RB tree of all runs with free space
  size_t object_size; // Size of object stored here, e.g. 192 bytes
  size_t run_length; // Total size of run, e.g. one page
  size_t available_registrations; // How many objects fit in a run of length run_length

  // Constructor
  arena_bin(); // "Decoy constructor"
  arena_bin(arena_hdr* parent, size_t _object_size);
  // Finalizer - once this is heaped
  void finalize_trees();

  // Delegation of malloc
  void* malloc();
  // Signal that a run is filled and should be dropped from the tree
  void filled_run(node_t* full_run);

};

// In order to create a list of arena_bins, they need a void
// constructor, no matter how much we promise to populate that list later.
// This "decoy constructor" will quietly create a blank, useless arena_bin,
// which gets immediately clobbered in the constructor of arena_chunk_hdr.

/*********
 * Arena *
 *********/

struct arena_hdr {
  // LOCK GOES HERE IN FUTURE
  tree_t normal_chunks; // rb tree of chunks that have large/small metadata
                        // and that still have available space
  byte* deepest; // Points to the deepest chunk or huge run allocated
  byte* free; // Points to a free list of chunks
  arena_bin bin_headers[NUM_SMALL_CLASSES]; // Store run metadata

  // Constructor
  arena_hdr();
  // Some parts of construction can only be done once this is heapified, since they
  // themselves require heap. This includes bin construction and trees
  void finalize();

  // Delegated malloc
  void* malloc(size_t size);
  // Find a chunk with space
  arena_chunk_hdr* retrieve_normal_chunk();
  // Make a new chunk for small/large allocations
  arena_chunk_hdr* add_normal_chunk();
  // Inserting a new chunk into the arena
  void insert_chunk(node_t* chunk);
  // Note that a normal chunk is full
  void filled_chunk(node_t* chunk);
  // Grow a normal chunk to take up more space
  size_t grow(arena_chunk_hdr* chunk);
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
  node_t chunk_tree_node; // Allows this to be part of an rbtree of runs for small/large assignments
  arena_hdr* parent; // Ptr to Arena
  size_t num_pages_available;
  size_t num_pages_allocated; // INITIAL_CHUNK_SIZE <= this <= FINAL_CHUNK_SIZE
                              // ...but don't forget the first page is the header
  tree_t clean_page_runs; // For clean *whole pages* for Large allocation
  uint8_t page_map[(FINAL_CHUNK_SIZE / PAGE_SIZE)]; // Stores state of each page
  // Note above - header data occupies the first free page slot.
  // Constructor
  arena_chunk_hdr(arena_hdr* _parent);
  void finalize_trees();

  // Expand heap by one chunk size, allocating the chunk for small or large page runs
  arena_chunk_hdr* add_normal_chunk();
  // Converter routines between page index and page address
  inline byte* get_page_location(size_t page_no);
  inline size_t get_page_index(byte* page_addr);
  // Find an unassigned page, write a small run header, and give it back
  small_run_hdr* carve_small_run(arena_bin* owner);
};


/**************
 * Small Runs *
 **************/

// Header entry for a small run, at the top of its page
struct small_run_hdr {
  node_t run_tree_node; // Allows this to be part of a rbtree of runs
  // LOCK GOES HERE IN FUTURE
  arena_bin* parent; // Pointer to our parent bin
  byte* free; // Pointer to start block of free list
  byte* next; // Pointer to first *never-allocated* block
  size_t free_cells; // How many free cells remain
  // Constructor
  small_run_hdr(arena_bin* _parent);
  // Delegated malloc
  void* malloc();
};

/**************
 * Large Runs *
 **************/

struct large_run_hdr {
  node_t page_tree_node; // For storage in rb tree of whole-page runs
  size_t formal_size; // True size of this allocation.
  size_t num_pages; // How many consecutive pages are assigned to this run
  // Constructor
  large_run_hdr(size_t _formal_size);
};

/*************
 * Huge runs *
 *************/

struct huge_run_hdr {
  size_t formal_size; // True size of the allocation
  size_t num_chunks; // How many consecutive chunks are assigned
  // Constructor
  huge_run_hdr(size_t _formal_size, size_t _num_chunks);
};

#endif /* ALLOC_TYPES_HEADER_GUARD */
