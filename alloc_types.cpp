// See alloc_types.h for thorough documentation on classes and structure.
#include <algorithm>
#include <stdio.h> // The most useful debugger
#include "alloc_types.h"
#include "assert.h"
#include "memlib.h" // Useful debugger

/*********************
 * Utility Functions *
 *********************/

// Get small size class of an allocation request
// Large and HUGE have different handling that
// comes in before this, so checking for those sizes here
// is not handy.

size_t get_small_size_class(size_t real_size) {
  assert(real_size <= MAX_SMALL_SIZE);
  // TODO: Replace with binary search, or something... good. 
  int i;
  // In ascending size order, look for smallest fit
  for(i=0; i<NUM_SMALL_CLASSES; i++) {
    if (real_size <= SMALL_CLASS_SIZES[i]) 
      return (i);
      // We don't want the size - we want the bin!
  }
  // PANIC! This doesn't actually fit in a small container!
  return (size_t)(-1);
}

// Get how many chunks are necessary for a huge allocation request
size_t get_num_chunks(size_t huge_allocation) {
  int num_chunks = 1;
  // There's a clear max size for a single data chunk, but we need
  // to account for the size of the header, too.
  if (huge_allocation > MAX_SINGLE_CHUNK) {
    num_chunks++;
    huge_allocation -= MAX_SINGLE_CHUNK;
  }
  // ...but after the first time there's no header
  num_chunks += (huge_allocation-1) / FINAL_CHUNK_SIZE;
  return num_chunks;
}

/*********
 * Arena *
 *********/

arena_hdr::arena_hdr() {
  free = NULL; // No free list initially

  // We really can't do anything else until we're on the heap.
  // It's hard to give children a pointer to us otherwise.

  // That chunk has normal metadata for small/large assignments,
  // so we should put it in our tree. Again, node_t <-> any header type
  /// ...but we can't do this while we're still on the stack!
}

// Called the moment we're allowed to work with the heap!
void arena_hdr::finalize() {
  // Now we have our final address, so we can initialize bins
  int ii;
  for (ii = 0 ; ii < NUM_SMALL_CLASSES ; ii++) {
    bin_headers[ii] = arena_bin(this, (size_t)SMALL_CLASS_SIZES[ii]);
    bin_headers[ii].finalize_trees();
  }
  // Also create and initialize a chunk. We can find its address.
  assert((mem_heap_lo() <= this) && (this <= mem_heap_hi()));
  arena_chunk_hdr* new_address = (arena_chunk_hdr*)((byte*)this + ARENA_HDR_SIZE);
  arena_chunk_hdr foo = arena_chunk_hdr(this);
  assert((mem_heap_lo() <= new_address) && (new_address <= mem_heap_hi()));
  *new_address = foo;
  // Take note that this, our first chunk, is the deepest chunk assigned.
  deepest = (byte*)new_address;
  tree_new(&normal_chunks);
}

void arena_hdr::insert_chunk(node_t* chunk) {
  assert((mem_heap_lo() <= chunk) && (chunk <= mem_heap_hi()));
  assert((mem_heap_lo() <= &normal_chunks) && (&normal_chunks <= mem_heap_hi()));
  tree_insert(&(normal_chunks), chunk);
}

// We need more space. We've got no chunks to expand. Let's try this.
arena_chunk_hdr* arena_hdr::add_normal_chunk() {
  arena_chunk_hdr* new_chunk = (arena_chunk_hdr*)mem_sbrk(INITIAL_CHUNK_SIZE);
  *new_chunk = arena_chunk_hdr(this);
  deepest = (byte*)new_chunk; // Take note that this is now the deepst chunk
  insert_chunk((node_t*) new_chunk); // Also, it's new and has space in it
  return new_chunk;
}

// Delegated malloc. Malloc if it's your responsibility, or delegate further.
void* arena_hdr::malloc(size_t size) {
  // Two cases we care about: HUGE allocations and Small allocations.
  // For the former, we do this ourselves.
  // For the latter, we delegate to our bins.

  if (size > MAX_LARGE_SIZE) {
    // Go into huge allocation mode
    size_t num_chunks = get_num_chunks(size);
    if (free != NULL) {
      // TODO: Try to pull something from the free list
    }
    // Uh-oh. The free list couldn't help us. This needs a *new chunk*.
    // Arena is going to demand new space on the heap! Single thread, everything fine.
    void* new_heap = mem_sbrk(num_chunks * FINAL_CHUNK_SIZE);
    assert(new_heap != NULL);
    // Write a new huge_run_hdr into the new space.
    *(huge_run_hdr*)new_heap = huge_run_hdr(size, num_chunks);
    // Take note of the deepst object assigned
    deepest = (byte*)new_heap;
    // OK, header in place - let's give them back the pointer, skipping the header
    return (void*) ((byte*) new_heap + HUGE_RUN_HDR_SIZE);

  } else if (size <= MAX_SMALL_SIZE) {
    // Make sure our sizer is working properly.
    assert (get_small_size_class(size) != -1);
    // Now make a bin do the work
    // Note - the bin no longer cares about the size.
    return bin_headers[get_small_size_class(size)].malloc();
  } else {
    // TODO: NOW: Make Large runs work
    // Look, I don't know, panic or something.
    // Crawl the page map to identify consecutive pages.
    return NULL;
  }
}

// Find a chunk that has a free page for a small run
arena_chunk_hdr* arena_hdr::retrieve_normal_chunk() {
  // We're getting corruption of normal_chunks; let's take extra care
  assert((mem_heap_lo() <= &normal_chunks) && (&normal_chunks <= mem_heap_hi()));
  node_t* avail_chunk = tree_find_min(&normal_chunks);
  if (avail_chunk != NULL) {
    // OK, we found one, simply give it back
    return (arena_chunk_hdr*)avail_chunk;
  } else {
    // OK, the whole chunk is full, and we need a new chunk
    // This shouldn't happen often
    // Arena is going to increase the size of the heap!
    return add_normal_chunk();
  }
};

// A chunk is full. Drop it.
void arena_hdr::filled_chunk(node_t* filled) {
  tree_remove(&normal_chunks, filled);
}

// Tell a chunk how many pages it is allowed to be, knowing that it has
// requested more pages.
size_t arena_hdr::grow(arena_chunk_hdr* chunk) {
  if ((byte*)chunk == deepest) {
    assert(chunk->num_pages_allocated * 2 <= FINAL_CHUNK_PAGES);
    return chunk->num_pages_allocated * 2;
  } else {
    // Something's already ahead of you! Grow, grow!
    return FINAL_CHUNK_PAGES;
  }
}

/**********************
 * Arena Chunk Header *
 **********************/

arena_chunk_hdr::arena_chunk_hdr(arena_hdr* _parent) {
  parent = _parent;
  num_pages_allocated = INITIAL_CHUNK_PAGES;
  num_pages_available = num_pages_allocated-1; // The header consumes one page

  // Initialize the page map
  memset(&page_map, FREE, (sizeof(uint8_t) * (FINAL_CHUNK_PAGES)));
  page_map[0] = HEADER;
}

void arena_chunk_hdr::finalize_trees() {
  tree_new(&clean_page_runs);
}

// You have free pages. Someone needs a small run. Go for it.
small_run_hdr* arena_chunk_hdr::carve_small_run(arena_bin* owner) {
  assert(num_pages_available > 0);
  num_pages_available--;

  if (num_pages_available == 0) {
    // Two options. Either we grow, or we ask to be removed from the availability list.
    if (num_pages_allocated < FINAL_CHUNK_PAGES) {
      num_pages_allocated = parent->grow(this);
    } else {
      parent->filled_chunk((node_t*)this);
    }
  }

  // Crawl the page map, looking for a place to fit
  // TODO: Use a tree implementation instead
  int ii;
  for (ii = 1 ; ii < num_pages_allocated ; ii++) {
    if (page_map[ii] == FREE) {
      small_run_hdr* new_page = (small_run_hdr*)get_page_location(ii);
      *new_page = small_run_hdr(owner);
      return new_page;
    }
  }
  // What? How did we get here, if there are no pages available!?
  return NULL;
  
}

// Conversion routines 

inline byte* arena_chunk_hdr::get_page_location(size_t page_no) {
  return ((byte*) this + (page_no * PAGE_SIZE));
}

inline size_t arena_chunk_hdr::get_page_index(byte* page_addr) {
  return (page_addr - (byte*) this) / PAGE_SIZE;
}


/*************
 * Arena Bin *
 *************/

// Decoy constructor used to help with list initialization
arena_bin::arena_bin() {
  current_run = NULL; // ...we're at least going to be safe about pointers.
};

// Proper constructor
arena_bin::arena_bin(arena_hdr* _parent, size_t _object_size) {
  parent = _parent;
  current_run = NULL;
  object_size = _object_size;
  run_length = PAGE_SIZE; // TODO: Assign multiple pages to runs of larger objects
  available_registrations = (PAGE_SIZE - SMALL_RUN_HDR_SIZE) / object_size;
}

void arena_bin::finalize_trees() {
  tree_new(&available_runs);
}

// Delegated malloc. Sorry, you're it - you're going to have to figure it out.
void* arena_bin::malloc() {
  // If we have a current run, we can ask it to malloc. But otherwise...
  if (current_run == NULL) {
    // All right, let's get a chunk from the tree then!
    node_t* new_run = tree_find_min(&available_runs);
    if (new_run != NULL) {
      current_run = (small_run_hdr*)new_run;
    } else {
      // Get a chunk from our parent
      arena_chunk_hdr* new_chunk = (parent->retrieve_normal_chunk());
      // Ask the chunk to carve a new small run to fit us
      current_run = new_chunk->carve_small_run(this);
    }
  }

  // We're set up either way, so now we can just have the run malloc
  return current_run->malloc(); 
}

// Note that a run is full and should not be considered for runs.
void arena_bin::filled_run(node_t* full_run) {
  tree_remove(&available_runs, full_run);
  if (full_run == (node_t*) current_run) { // Not anymore!
    current_run = NULL;
  }
}

/*******************
 * Huge Run Header *
 *******************/

huge_run_hdr::huge_run_hdr(size_t _formal_size, size_t _num_chunks) {
  formal_size = _formal_size;
  num_chunks = _num_chunks;
}

/********************
 * Large Run Header *
 ********************/

large_run_hdr::large_run_hdr(size_t _formal_size) {
  // node_t needs no initialization; the node is made
  formal_size = _formal_size;
  num_pages = (formal_size % PAGE_SIZE ? (formal_size/PAGE_SIZE + 1) : (formal_size/PAGE_SIZE));
}


/********************
 * Small Run Header *
 ********************/

small_run_hdr::small_run_hdr(arena_bin* _parent) {
  // node_t needs no initialization; the node is made
  parent = _parent;
  free = NULL; // There is no free list
  // The first cell is offset from the header by the header size
  next = ((byte*)this + SMALL_RUN_HDR_SIZE);//
  free_cells = parent->available_registrations;
}

void* small_run_hdr::malloc() {
  // We *really* shouldn't be asked if we have no free space - this is a cleanup error
  assert(free_cells > 0);
  byte* new_address = NULL; //What we're giving the user
  free_cells--; // We've lost a free cell!

  // If no space left, get us off the tree! We don't want any more allocations
  if (free_cells == 0) {
    // We're also a node_t, so ask the parent to remove us
    parent->filled_run((node_t*)this);
  }

  if (free != NULL) {
    // Grab the head of the free list
    new_address = free;
    // Pop it off and chain the free pointer down
    free = (byte*) *free;
    // Give the user the space
  } else {
    // OK, so we don't have a free list.
    // Get a new cell from the never-used pointer
    new_address = next;
    // Bump up the never-used pointer for next time
    next += parent->object_size;
  }

  return (void*) new_address;
}
