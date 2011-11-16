#ifndef ALLOC_TYPES_HEADER_GUARD
#define ALLOC_TYPES_HEADER_GUARD

#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Contains memset
#include <pthread.h> // Contains infinite amounts of fun
#include "rbtree.h"
#include "memlib.h" // Access to sbrk, mem_heap_lo, mem_heap_hi

#define MAX_SIZE_T (size_t)(-1)

// This file defines all data structures used in the malloc
// implementation, such as run headers and bin metadata.

/****************
 * Debug Macros *
 ****************/

// Currently, let's always use DEBUG_PRINT_TRACE if DEBUG is set
#ifdef DEBUG
//#define DEBUG_PRINT_TRACE
#endif

#ifdef DEBUG_PRINT_TRACE
#define PRINT_TRACE(...) printf( __VA_ARGS__ )
#else
#define PRINT_TRACE(...) do {} while(0);// Do nothing
#endif

/*****************
 * On Finalizers *
 *****************/

// Our many awesome control structures must be created on the stack,
// then written to the heap. This means no pointer initialization during 
// the constructor! If you need to do pointer setup, do it in the 
// object's finalize() method, which we agree to call only after it's
// placed on the heap.

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

/* Returns true if p is ALIGNMENT-byte aligned */
#if (__WORDSIZE == 64 )
#define IS_ALIGNED(p)  ((((uint64_t)(p)) % ALIGNMENT) == 0)
#else
#define IS_ALIGNED(p)  ((((uint32_t)(p)) % ALIGNMENT) == 0)
#endif

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
#define INITIAL_CHUNK_SIZE (64 * PAGE_SIZE) // 256 kB
#define INITIAL_CHUNK_PAGES (INITIAL_CHUNK_SIZE / PAGE_SIZE)
// Maximum chunk size; maximum size given to an arena
#define FINAL_CHUNK_SIZE (64 * PAGE_SIZE) // 256 kB
#define FINAL_CHUNK_PAGES (FINAL_CHUNK_SIZE / PAGE_SIZE)
// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

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

// Anything larger than this size must be given at least one page
// This must be updated if tables are updated!
#define MAX_SMALL_SIZE (3840)
// Anything larger than this must be given at least one chunk
#define MAX_LARGE_SIZE (FINAL_CHUNK_SIZE - PAGE_SIZE - LARGE_RUN_HDR_SIZE) // Note - one page always allocated to header
// Anything larger than this must be given at least *two* chunks
#define MAX_SINGLE_CHUNK (FINAL_CHUNK_SIZE - HUGE_RUN_HDR_SIZE)
// Anything large than this must be given at least *two* pages
#define MAX_SINGLE_PAGE (PAGE_SIZE - LARGE_RUN_HDR_SIZE)

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
  {   8, 
     16,   32,   48,   64,   80,   96,  112,  128,
    192,  256,  320,  384,  448,  512,
    768, 1024, 1280, 1536, 1792, 
   2048, 2304, 2560, 2816, 
   3072, 3328, 3584, 3840}; 

// Some of the bigger small-class sizes really want extra pages
// for their runs. This reduces fragmentation from rounding up.
const uint8_t SMALL_CLASS_RUN_PAGE_USAGE[NUM_SMALL_CLASSES] =
  {   1,
      1,    1,    1,    1,    1,    1,    1,    1, 
      1,    1,    1,    1,    1,    1,
      1,    1,    1,    1,    2,
      2,    2,    2,    2, 
      3,    3,    3,    3
  };

/**********************
 * Arena Bin Metadata *
 **********************/

// Defined first because so many things care what size it is.
// Other structures are defined in descending size order.

class arena_bin {

  // ** Member Data ** 
 public:
  arena_hdr* parent;
  small_run_hdr* current_run; // Pointer to header of current run
  tree_t available_runs; // RB tree of all runs with free space
  size_t object_size; // Size of object stored here, e.g. 192 bytes
  size_t run_length; // Total size of run, e.g. one page
  size_t available_registrations; // How many objects fit in a run of length run_length

 private:
  // Internal locks, accessed through external methods lock and unlock
  pthread_mutex_t bin_lock; // Must be taken out to create or free chunks, or to do HUGE allocations


  // ** Methods **
 public:
  // Constructor
  arena_bin(); // "Decoy constructor"
  arena_bin(arena_hdr* parent, size_t _object_size, size_t num_pages);
  // Finalizer - once this is heaped
  void finalize();

  // Manipulate locks
  inline void lock() { pthread_mutex_lock(&bin_lock); }
  inline void unlock() { pthread_mutex_unlock(&bin_lock); }

  // Internal consistency checker
  int check();
  // Delegation of malloc
  void* malloc();
  // Signal that a run is new or recently unfilled and should be added
  // to the tree
  void run_available(node_t* avail_run);
  // Signal that a run is filled and should be dropped from the tree
  void filled_run(node_t* full_run);

 private:
  inline void lock_init() { pthread_mutex_init(&bin_lock, NULL); }

};

// In order to create a list of arena_bins, they need a void
// constructor, no matter how much we promise to populate that list later.
// This "decoy constructor" will quietly create a blank, useless arena_bin,
// which gets immediately clobbered in the constructor of arena_chunk_hdr.

/*********
 * Arena *
 *********/

class arena_hdr {
  // ** Member Data **
 public:
  tree_t normal_chunks; // rb tree of chunks that have large/small metadata
                                 // and that still have available space
  
 private:
  pthread_mutex_t arena_lock;
  size_t* deepest; // Points to the deepest chunk or huge run allocated
  size_t* free_list; // Points to a free list of chunks
  arena_bin bin_headers[NUM_SMALL_CLASSES]; // Store run metadata


  // ** Methods **
 public:
  // Constructor
  arena_hdr();
  // Some parts of construction can only be done once this is heapified, since they
  // themselves require heap. This includes bin construction and trees
  void finalize();

  // Delegated heap consistency checker
  int check();
  // Delegated memory management
  void* malloc(size_t size);
  void free(void* ptr);
  void* realloc(void* ptr, size_t size, size_t old_size);

  // Lock management
  inline void lock() { pthread_mutex_lock(&arena_lock); }
  inline void unlock() { pthread_mutex_unlock(&arena_lock); }

  // Determine size of an allocation
  size_t size_of_alloc(void* ptr);

  // Make a new chunk for small/large allocations
  arena_chunk_hdr* add_normal_chunk();
  // Inserting a new chunk into the arena
  void insert_chunk(node_t* chunk);
  // Note that a normal chunk is full
  void filled_chunk(node_t* chunk);
  // Grow a normal chunk to take up more space
  size_t grow(arena_chunk_hdr* chunk);
  size_t grow_max(arena_chunk_hdr* chunk);

 private:
  inline void lock_init() { pthread_mutex_init(&arena_lock, NULL); }

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

class arena_chunk_hdr {
  // ** Member Data **
 public:
  node_t chunk_tree_node; // Allows this to be part of an rbtree of runs for small/large assignments
  arena_hdr* parent; // Ptr to Arena
  size_t num_pages_available;
  size_t num_pages_allocated; // INITIAL_CHUNK_SIZE <= this <= FINAL_CHUNK_SIZE
                                       // ...but don't forget the first page is the header
  uint8_t page_map[(FINAL_CHUNK_SIZE / PAGE_SIZE)]; // Stores state of each page
  // Note above - header data occupies the first free page slot.

 private:
  pthread_mutex_t chunk_lock;

  // ** Methods **
 public:
  // Constructor
  arena_chunk_hdr(arena_hdr* _parent);
  void finalize();
  // Internal consistency checker
  int check();

  // Lock manipulation
  inline void lock() { pthread_mutex_lock(&chunk_lock); }
  inline void unlock() { pthread_mutex_unlock(&chunk_lock); }

  // It can't malloc directly, but it does have free and realloc responsibilities
  void free(void* ptr);
  void* realloc(void* ptr, size_t size, size_t old_size);
  // Get size of allocation by pointer
  size_t size_of_alloc(void* ptr);

  // Expand heap by one chunk size, allocating the chunk for small or large page runs
  arena_chunk_hdr* add_normal_chunk();
  // Find a run of N consecutive pages to fit a Large allocation.
  void* fit_large_run(size_t consec_pages);
  // Find an unassigned page, write a small run header, and give it back
  small_run_hdr* carve_small_run(arena_bin* owner);

  // Converter routines between page index and page address
  inline byte* get_page_location(size_t page_no);
  inline size_t get_page_index(byte* page_addr);

 private:
  inline void lock_init() { pthread_mutex_init(&chunk_lock, NULL); }

};


/**************
 * Small Runs *
 **************/

// Header entry for a small run, at the top of its page
struct small_run_hdr {
  // ** Member Data **
  node_t run_tree_node; // Allows this to be part of a rbtree of runs
  //pthread_mutex_t small_run_lock;
  arena_bin* parent; // Pointer to our parent bin
  size_t* free_list; // Pointer to start block of free list
  size_t* next; // Pointer to first *never-allocated* block
  size_t free_cells; // How many free cells remain

  // ** Methods **
  // Constructor
  small_run_hdr(arena_bin* _parent);
  // Finalizer
  void finalize();

  // Internal consistency check
  int check();
  // Delegated malloc, free, realloc
  void* malloc();
  void free(void* ptr);
  void* realloc(void* ptr, size_t size, size_t old_size);
};

/**************
 * Large Runs *
 **************/

struct large_run_hdr {
  // node_t page_tree_node; // For storage in rb tree of whole-page runs
  // currently unused

  //size_t formal_size; // True size of this allocation.
  size_t num_pages; // How many consecutive pages are assigned to this run
  // Constructor
  large_run_hdr(size_t _num_pages);
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
