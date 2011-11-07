// See alloc_types.h for thorough documentation on classes and structure.
#include <algorithm>
#include <stdio.h> // The most useful debugger
#include <stdlib.h>
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
    if (real_size <= SMALL_CLASS_SIZES[i]) {
      return (i);
      // We don't want the size - we want the bin!
    }
  }
  // PANIC! This doesn't actually fit in a small container!
  assert(0); // Nothing to check here - we *did* screw up.
  return MAX_SIZE_T;
}

// Get how many chunks are necessary for a HUGE allocation request
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

// Get how many chunks are necessary for a Large allocation request
size_t get_num_pages(size_t large_allocation) {
  int num_pages = 1;
  if (large_allocation > MAX_SINGLE_PAGE) {
    num_pages++;
    large_allocation -= MAX_SINGLE_PAGE;
  }
  // ...but after the first time there's no header
  num_pages += (large_allocation-1) / PAGE_SIZE;
  return num_pages;
}

/*********
 * Arena *
 *********/

arena_hdr::arena_hdr() {
  free_list = NULL; // No free list initially

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
    bin_headers[ii] = arena_bin(this, (size_t)SMALL_CLASS_SIZES[ii], 
				(size_t)SMALL_CLASS_RUN_PAGE_USAGE[ii]);
    bin_headers[ii].finalize_trees();
  }
  // Also create and initialize a chunk. We can find its address.
  assert((mem_heap_lo() <= this) && (this <= mem_heap_hi()));
  arena_chunk_hdr* new_address = (arena_chunk_hdr*)((byte*)this + ARENA_HDR_SIZE);
  arena_chunk_hdr foo = arena_chunk_hdr(this);
  assert((mem_heap_lo() <= new_address) && (new_address <= mem_heap_hi()));
  *new_address = foo;
  // Take note that this, our first chunk, is the deepest chunk assigned.
  deepest = (size_t*)new_address;
  tree_new(&normal_chunks);
}

void arena_hdr::insert_chunk(node_t* chunk) {
  assert((mem_heap_lo() <= chunk) && (chunk <= mem_heap_hi()));
  assert((mem_heap_lo() <= &normal_chunks) && (&normal_chunks <= mem_heap_hi()));
  PRINT_TRACE("Inserting a chunk into a tree; did you know that?\n");
  assert(tree_search(&normal_chunks, chunk) == NULL);
  tree_insert(&(normal_chunks), chunk);
}

// We need more space. We've got no chunks to expand. Let's try this.
arena_chunk_hdr* arena_hdr::add_normal_chunk() {
  arena_chunk_hdr* new_chunk = (arena_chunk_hdr*)mem_sbrk(INITIAL_CHUNK_SIZE);
  *new_chunk = arena_chunk_hdr(this);
  deepest = (size_t*)new_chunk; // Take note that this is now the deepst chunk
  insert_chunk((node_t*) new_chunk); // Also, it's new and has space in it
  return new_chunk;
}

// Delegated malloc. Malloc if it's your responsibility, or delegate further.
void* arena_hdr::malloc(size_t size) {
  // Two cases we care about: HUGE allocations and Small allocations.
  // For the former, we do this ourselves.
  // For the latter, we delegate to our bins.
  PRINT_TRACE("Entering malloc at the arena level for (%zu).\n", size);
  if (size > MAX_LARGE_SIZE) {

    // ** Use Huge Mode **

    PRINT_TRACE(" Using a HUGE allocation.\n");
    size_t num_chunks = get_num_chunks(size);
    PRINT_TRACE(" Number of chunks is %lu\n", num_chunks);
    if (free_list != NULL) {
      // TODO: Try to pull something from the free list
      // TODO: We currently don't have a free list for chunks
      // Later we'll have a structure that coalesces chunks
      // and uses them to allocate huge objects
      PRINT_TRACE(" The free list has some space; try to pull something from the free list");
    }
    // Uh-oh. The free list couldn't help us. This needs a *new chunk*.
    // Arena is going to demand new space on the heap! Single thread, everything fine.
    PRINT_TRACE(" Creating a new chunk for this allocation.\n");
    // A point of care: It may be the case that we have an ungrown arena chunk
    // on top right now. We need to align the new chunk on top of that.
    if ((byte*)mem_heap_hi() + 1 - (byte*)mem_heap_lo() - ARENA_HDR_SIZE % FINAL_CHUNK_SIZE) {
      // Allocate heap up to the next chunk boundary. If we got here, this is a small run.
      grow_max((arena_chunk_hdr*)deepest);
    }
    void* new_heap = mem_sbrk(num_chunks * FINAL_CHUNK_SIZE);
    PRINT_TRACE(" Increased the heap by %lu\n", num_chunks * FINAL_CHUNK_SIZE);
    assert(new_heap != NULL);
    // Write a new huge_run_hdr into the new space.
    *(huge_run_hdr*)new_heap = huge_run_hdr(size, num_chunks);
    // Take note of the deepst object assigned
    deepest = (size_t*)new_heap;
    // OK, header in place - let's give them back the pointer, skipping the header
    void* new_address = ((byte*) new_heap + HUGE_RUN_HDR_SIZE);
    PRINT_TRACE(" ...succeeded, at %p.\n", new_address);
    return (void*) (new_address);

  } else if (size <= MAX_SMALL_SIZE) {

    // ** Use Small Mode **

    PRINT_TRACE(" Using a small allocation.\n");
    // Make sure our sizer is working properly.
    assert (get_small_size_class(size) != MAX_SIZE_T);
    // Now make a bin do the work
    // Note - the bin no longer cares about the size.
    PRINT_TRACE(" ...delegating to bin %zu (%d).\n", get_small_size_class(size), SMALL_CLASS_SIZES[get_small_size_class(size)]);
    size_t bin_index = get_small_size_class(size);
    return bin_headers[bin_index].malloc();
  } else {

    // ** Use Large Mode **

    PRINT_TRACE(" Using a Large allocation.\n");
    // We need to ask chunks to try to fit this thing.
    // Fortunately, that is *probably* just a tree lookup.
    node_t* lowest_normal_chunk = tree_first(&normal_chunks);
    size_t consec_pages = get_num_pages(size);
    byte* new_address;
    while (lowest_normal_chunk != NULL) {
      PRINT_TRACE(" ...asking chunk %p to fit %zu pages...\n", lowest_normal_chunk, consec_pages);
      new_address = (byte*)((arena_chunk_hdr*)(lowest_normal_chunk))->fit_large_run(consec_pages);
	if (new_address != NULL) {
	  // Got one! Bookkeeping has been done already
	  PRINT_TRACE(" ...succeeded, at %p.\n", new_address);
	  return new_address;
	}
      lowest_normal_chunk = tree_next(&normal_chunks, lowest_normal_chunk);
    }
    PRINT_TRACE(" ...couldn't find any space, so we need a new chunk.\n");
    // Allocate and prepare a new chunk
    arena_chunk_hdr* new_chunk = add_normal_chunk();
    // A new chunk *will* have space for a Large allocation
    return new_chunk->fit_large_run(consec_pages);
  }
}

// Delegated free
void arena_hdr::free(void* ptr) {
  // Determine if this is a HUGE allocation. We know if this is a HUGE allocation if it's
  // on a chunk boundary.
  // First, get the distance from the end of the header (ptr - this)
  // Then, subtract the arena metadata offset (ARENA_HDR_SIZE)
  // If that falls on the first page of a multiple of FINAL_CHUNK_SIZE we are in business.
  
  size_t header_offset = ((byte*)(ptr) - (byte*)this - ARENA_HDR_SIZE);

  if (header_offset % FINAL_CHUNK_SIZE <= PAGE_SIZE ) {
    PRINT_TRACE("Deallocating a HUGE chunk at %p.\n", ptr);
    // We know by computation this lies on a HUGE chunk boundary and
    // is a HUGE allocation
    // Find HUGE allocation header
    huge_run_hdr* header = (huge_run_hdr*)(((byte*)(ptr)) - HUGE_RUN_HDR_SIZE);
    PRINT_TRACE(" Header data located at %p.\n", header);
    // OK, now we can get freeing! Iteratively add freed chunks to the free list
    // We keep the free list sorted for contiguity checks. 
    // Assemble the free list links
    PRINT_TRACE(" Writing %zu internal headers.\n", (header->num_chunks -1));
    int ii;
    for (ii = 0 ; ii < (header->num_chunks - 1) ; ii++) {
      // Write the address of the next free chunk at the top of this free chunk
      // ...by casting as a pointer to a pointer, and writing a pointer to it
      PRINT_TRACE("  ...at %p, linking %p...\n", ((byte*)(header)) + FINAL_CHUNK_SIZE * ii, (size_t*)((byte*)(header) + FINAL_CHUNK_SIZE * (ii+1)));
      *(size_t**)(((byte*)(header)) + FINAL_CHUNK_SIZE * ii) = (size_t*)((byte*)(header) + FINAL_CHUNK_SIZE * (ii+1));
    }

    // Also, save the first link target and last link site to help us
    // The first chunk link address is just the header
    size_t** last_chunk_link_site = (size_t**)(((byte*)(header)) + FINAL_CHUNK_SIZE * ii);
    
    if (free_list == NULL) {
      PRINT_TRACE(" Creating a chunk free list.\n");
      // Attach out segment to the free list
      free_list = (size_t*)header;
      *last_chunk_link_site = NULL;
    } else {
      PRINT_TRACE(" Hey, we already have a free list!\n");
      size_t * curr = *(size_t**)free_list;
      size_t * prev = free_list;
      PRINT_TRACE(" Recursing free list...\n");

      while ((curr != NULL) && (curr < (size_t*)header)) {
	prev = curr;
	curr = (size_t *) *curr;
      }

      *(size_t **)(prev) = (size_t *)header;
      *(size_t **)last_chunk_link_site = (size_t *)(curr);
    }
  } else {
    PRINT_TRACE("I saw a header_offset of %zu, so I'm asking a chunk to free.\n", header_offset);
    // Which chunk is this in? Try using header_offset / FINAL_CHUNK_SIZE to index
    arena_chunk_hdr* owning_chunk = (arena_chunk_hdr*)((byte*)this + ARENA_HDR_SIZE + (header_offset/FINAL_CHUNK_SIZE)*FINAL_CHUNK_SIZE);
    PRINT_TRACE("...I think chunk %p (%zu chunks forward) will do.\n", owning_chunk, header_offset/FINAL_CHUNK_SIZE);
    // Delegate!
    owning_chunk->free(ptr);
  }
}

// Find a chunk that has a free page for a small run
arena_chunk_hdr* arena_hdr::retrieve_normal_chunk() {
  // We're getting corruption of normal_chunks; let's take extra care
  assert((mem_heap_lo() <= &normal_chunks) && (&normal_chunks <= mem_heap_hi()));
  node_t* avail_chunk = tree_first(&normal_chunks);
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
  // Removing something not in the tree is bad!
  assert(tree_search(&normal_chunks, filled) != NULL);
  tree_remove(&normal_chunks, filled);
}

// Tell a chunk how many pages it is allowed to be, knowing that it has
// requested more pages.
size_t arena_hdr::grow(arena_chunk_hdr* chunk) {
  if ((size_t*)chunk == deepest) {
    PRINT_TRACE("Growing the deepest chunk.\n");
    assert(chunk->num_pages_allocated * 2 <= FINAL_CHUNK_PAGES);
    // We have open VM ahead of us
    mem_sbrk(chunk->num_pages_allocated * PAGE_SIZE);
    return chunk->num_pages_allocated * 2;
  } else {
    PRINT_TRACE("Fully inflating a chunk that's not the deepest.\n");
    // Something's already ahead of you! Grow, grow!
    return FINAL_CHUNK_PAGES;
  }
}

// You know, for a fact, that you want a chunk grown to max size
size_t arena_hdr::grow_max(arena_chunk_hdr* chunk) {
  if ((size_t*)chunk == deepest) {
    PRINT_TRACE("Maxing out a chunk!\n");
    mem_sbrk((FINAL_CHUNK_PAGES - chunk->num_pages_allocated) * PAGE_SIZE);
    return FINAL_CHUNK_PAGES;
  } else {
    // grow(chunk) will inflate this anyway
    return grow(chunk);
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

// An arena has told us this memory belongs to us. Free it.
void arena_chunk_hdr::free(void* ptr) {
  size_t bin = get_page_index((byte*)ptr);
  PRINT_TRACE("  arena_chunk_hdr has located a pointer into bin %zu (%d).\n", bin, page_map[bin]);
  assert((page_map[bin] == SMALL_RUN_HEADER) || 
	 (page_map[bin] == SMALL_RUN_FRAGMENT) ||
	 (page_map[bin] == LARGE_RUN_HEADER));
  if (page_map[bin] == LARGE_RUN_HEADER) {
    size_t num_chunks = ((large_run_hdr*)get_page_location(bin))->num_pages;
    int ii;
    for(ii = 0 ; ii < num_chunks ; ii++) {
      page_map[bin + ii] = FREE;
      // TODO: OPT: Treed page run management
    }
    // Note that cells have been returned for rapid bookkeeping
    if ((num_pages_available == 0) && (num_pages_allocated == FINAL_CHUNK_PAGES)) {
      // We're about to stop being full
      PRINT_TRACE("Inserting a chunk into normal chunks.\n");
      assert(tree_search(&(parent->normal_chunks), (node_t*)this) == NULL);
      tree_insert(&(parent->normal_chunks), (node_t*)this);
    }
    num_pages_available += num_chunks;
  } else if (page_map[bin] == SMALL_RUN_HEADER) {
    // It's a small header - delegate!
    ((small_run_hdr*)get_page_location(bin))->free(ptr);
  } else {
    // Oops. They want something in the middle of a multi-page small run.
    // You'll need to find the appropriate control structure.
    while (page_map[bin] == SMALL_RUN_FRAGMENT) {
      bin--;
    }
    assert(page_map[bin] == SMALL_RUN_HEADER);
    ((small_run_hdr*)get_page_location(bin))->free(ptr);
  }
}

// TODO: OPT: Replace all this with tree management in clean_page_runs
// Can coalesce there. Or really, make this anything less painful than linear search

// You have free pages. Do you have consec_pages in a row? Make a large run there.
void* arena_chunk_hdr::fit_large_run(size_t consec_pages) {
  PRINT_TRACE("  Trying to fit into chunk %p, which has %zu free pages (%zu total).\n", this, num_pages_available, num_pages_allocated);

  // If you have enough free pages, the attempt can be made
  if (consec_pages <= num_pages_available) {
    PRINT_TRACE("   Making fit attempt, at least.\n");
    int consec = 0;
    int ii;
    for (ii = 1 ; ii < num_pages_allocated ; ii++) {
      if (page_map[ii] == FREE) {
	consec++;
	if (consec == consec_pages) {
	  // We've found space for a large run. Make it so.
	  int start_point = ii + 1 - consec;
	  PRINT_TRACE("  We've found consecutive slots for the large allocation.\n");
	  PRINT_TRACE("  %zu of them, starting at %d (%p)\n", consec_pages, start_point, get_page_location(start_point));
	  page_map[start_point] = LARGE_RUN_HEADER;
	  int jj;
	  for (jj = 1 ; jj < consec_pages ; jj++) {
	    page_map[start_point + jj] = LARGE_RUN_FRAGMENT;
	  }
	  byte* new_address = get_page_location(start_point);
	  *(large_run_hdr*)new_address = large_run_hdr(consec_pages);
	  num_pages_available -= consec_pages;
	  if ((num_pages_available == 0) && (num_pages_allocated == FINAL_CHUNK_PAGES)) {
	    PRINT_TRACE("--Chunk is definitely full--\n");
	    assert(tree_search(&(parent->normal_chunks), (node_t*)this) != NULL);
	    tree_remove(&(parent->normal_chunks), (node_t*)this);
	  }
	  // This returns the *address* for use.
	  return (new_address + LARGE_RUN_HDR_SIZE);
	}
      } else {
	consec = 0;
      }
    }
  }

  if ((FINAL_CHUNK_PAGES - num_pages_allocated) > consec_pages) {
    // We've determined growing can work. Note: If there are no small runs, growing MAY work,
    // but you are on dangerous ground there.
    PRINT_TRACE("  Growing chunk for large run.\n");
    PRINT_TRACE("  We need %zu pages, and are currently %zu big.\n", consec_pages, num_pages_allocated);
    size_t old_allocation = num_pages_allocated;
    // Grow generously
    while ((num_pages_allocated - old_allocation) < consec_pages) {
      num_pages_allocated = parent->grow(this);
      PRINT_TRACE("  ...%zu big...\n", num_pages_allocated);
    }
    num_pages_available += (num_pages_allocated - old_allocation);

    // At this point, we know perfectly well the *first* N new pages are open
    // ...but maybe a few more, too.
    int ii, jj;
    size_t start_point = 1; // 0 contains header data, so you're not using that!
    for (ii = old_allocation ; ii > 0 ; ii--) {
      PRINT_TRACE("   Backwalking page %d looking for end-of-free...\n", ii);
      if (page_map[ii] != FREE) {
	PRINT_TRACE("   ...but it's safe to start at page %d.\n", ii+1);
	start_point = ii+1;
	break;
      }
    }
    page_map[start_point] = LARGE_RUN_HEADER;
    for (jj = 1 ; jj < consec_pages ; jj++) {
      page_map[start_point + jj] = LARGE_RUN_FRAGMENT;
    }
    byte* new_address = get_page_location(start_point);
    // TREE OK HERE
    *(large_run_hdr*)new_address = large_run_hdr(consec_pages);
    // TREE HOSED HERE
    num_pages_available -= consec_pages;
    if ((num_pages_available == 0) && (num_pages_allocated == FINAL_CHUNK_PAGES)) {
      PRINT_TRACE("--Chunk is definitely full--\n");
      assert(tree_search(&(parent->normal_chunks), (node_t*)this) != NULL);
      tree_remove(&(parent->normal_chunks), (node_t*)this);
    }
    return (new_address + LARGE_RUN_HDR_SIZE);

  } else {
    PRINT_TRACE("  ...but this chunk can't fit it even by growing (currently %zu pages).\n", this->num_pages_allocated);
    return NULL;
  }
}

// You have free pages. Someone needs a small run. Go for it.
small_run_hdr* arena_chunk_hdr::carve_small_run(arena_bin* owner) {
  PRINT_TRACE("  Entering small run carver to allocate %zu consecutive pages.\n", owner->run_length / PAGE_SIZE);
  PRINT_TRACE("   Before allocating, we have %zu pages left.\n", num_pages_available);

  size_t consec_pages = owner->run_length / PAGE_SIZE;

  if (consec_pages < num_pages_available) {
    // We can at least try to fit
    
    // Crawl the page map, looking for a place to fit
    // TODO: Use a tree implementation instead
    int consec = 0;
    int ii;
    for (ii = num_pages_allocated-1 ; ii >= 0 ; ii--) {
      if (page_map[ii] == FREE) {
	consec++;
	if (consec == consec_pages) {
	  PRINT_TRACE("   We've found consecutive slots for the small allocation.\n");
	  PRINT_TRACE("  %zu of them, starting at %d (%p)\n", consec_pages, ii, get_page_location(ii));
	  small_run_hdr* new_page = (small_run_hdr*)get_page_location(ii);
	  PRINT_TRACE("   Installing new small run at %p.\n", new_page);
	  *new_page = small_run_hdr(owner);
	  new_page->finalize();
	  page_map[ii] = SMALL_RUN_HEADER;
	  
	  int jj; 
	  for (jj = 1 ; jj < consec_pages ; jj++) {
	    page_map[ii+jj] = SMALL_RUN_FRAGMENT;
	  }
	  // Let's finish the construction properly by making it available
	  // to the owner of bins of that size
	  owner->run_available((node_t*) new_page);
	  num_pages_available -= consec_pages;
	  // This returns the *run* for use.
	  return new_page;
	}
      } else {
	consec = 0;
      }
    }
  }

  // Well, that didn't help. How about growing? Does that help?
  if ((FINAL_CHUNK_PAGES - num_pages_allocated) > consec_pages) {
    PRINT_TRACE("   Growing chunk for small run.\n");
    size_t old_allocation = num_pages_allocated;
    while ((num_pages_allocated - old_allocation) < consec_pages) {
      num_pages_allocated = parent->grow(this);
      PRINT_TRACE("  ...%zu big...\n", num_pages_allocated);
    }
    num_pages_available = (num_pages_allocated - old_allocation);

    // At this point, we know perfectly well the last N pages are fair game
    int ii = num_pages_allocated - consec_pages, jj; // Imagine a +1, -1 there
    page_map[ii] = SMALL_RUN_HEADER;
    for (jj = 1 ; jj < consec_pages ; jj++) {
      page_map[ii+jj] = SMALL_RUN_FRAGMENT;
    }
    small_run_hdr* new_page = (small_run_hdr*)get_page_location(ii);
    *new_page = small_run_hdr(owner);
    new_page->finalize();
    owner->run_available((node_t*) new_page);
    num_pages_available -= consec_pages;
    return new_page;

  } else {
    PRINT_TRACE("   Even a grown chunk won't fit this; try somewhere else.\n");
    return NULL;
  }
  
  // Sorry, friend. You'll have to go somewhere else.
  return NULL;  
}

// Conversion routines 

inline byte* arena_chunk_hdr::get_page_location(size_t page_no) {
  return ((byte*)this + (page_no * PAGE_SIZE));
}

inline size_t arena_chunk_hdr::get_page_index(byte* page_addr) {
  return (page_addr - (byte*)this) / PAGE_SIZE;
}


/*************
 * Arena Bin *
 *************/

// Decoy constructor used to help with list initialization
arena_bin::arena_bin() {
  current_run = NULL; // ...we're at least going to be safe about pointers.
};

// Proper constructor
arena_bin::arena_bin(arena_hdr* _parent, size_t _object_size, size_t num_pages) {
  parent = _parent;
  current_run = NULL;
  object_size = _object_size;
  run_length = PAGE_SIZE * num_pages; // TODO: Assign multiple pages to runs of larger objects
  available_registrations = (run_length - SMALL_RUN_HDR_SIZE) / object_size;
}

void arena_bin::finalize_trees() {
  tree_new(&available_runs);
}

// Delegated malloc. Sorry, you're it - you're going to have to figure it out.
void* arena_bin::malloc() {
  PRINT_TRACE(" Entering malloc at the arena_bin level.\n");
  // If we have a current run, we can ask it to malloc. But otherwise...
  if (current_run == NULL) {
    PRINT_TRACE("  No current run; choosing from tree.\n");
    // All right, let's get a chunk from the tree then!
    node_t* new_run = tree_first(&available_runs);
    if (new_run != NULL) {
      PRINT_TRACE("  ...got a run from the tree (%p).\n", new_run);
      current_run = (small_run_hdr*)new_run;
    } else {
      // Get a chunk from our parent
      PRINT_TRACE("  No good, we need a chunk from a parent.\n");
      node_t* new_chunk; 
      byte* new_address;
      new_chunk = tree_first(&parent->normal_chunks);
      while (new_chunk != NULL) {
	PRINT_TRACE("  ...asking chunk %p to fit %zu pages...\n", new_chunk, run_length/PAGE_SIZE);
	new_address = (byte*)(((arena_chunk_hdr*)(new_chunk))->carve_small_run(this));
	if (new_address != NULL) {
	  // A new small run has been allocated for us. Move along.
	  PRINT_TRACE("   ...succeeded, at %p.\n", new_address);
	  current_run = (small_run_hdr*)new_address;
	  break;
	}
	new_chunk = tree_next(&parent->normal_chunks, new_chunk);
      }
      if (new_address == NULL) {
	PRINT_TRACE("  Argh! There's not a single chunk we can work with.\n");
	// More space! Parent, take care of it.
	new_chunk = (node_t*)parent->add_normal_chunk();
	current_run = ((arena_chunk_hdr*)new_chunk)->carve_small_run(this);
      }
    }
  } else {
    PRINT_TRACE("  We're just going to use the current run at %p.\n", current_run);
  }
  assert(current_run != NULL);
  PRINT_TRACE("  Assigning this allocation to the run at %p.\n", current_run);
  PRINT_TRACE("  ...which is serving objects of size %zu.\n", current_run->parent->object_size);
  // We're set up either way, so now we can just have the run malloc
  return current_run->malloc(); 
}

void arena_bin::run_available(node_t* avail_run) {
  // Make sure we don't somehow have a duplicate entry
  assert(tree_search(&available_runs, avail_run) == NULL);
  tree_insert(&available_runs, avail_run);
}

// Note that a run is full and should not be considered for runs.
void arena_bin::filled_run(node_t* full_run) {
  // You can only remove a run from a tree if it exists
  assert(tree_search(&available_runs, full_run) != NULL);
  tree_remove(&available_runs, full_run);
  assert(tree_search(&available_runs, full_run) == NULL);
  if (full_run == (node_t*) current_run) { // Not anymore!
    PRINT_TRACE("  ...and it was the current run.\n");
    current_run = NULL;
  } else {
    PRINT_TRACE("  ...but I don't think it was the current run.\n");
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

large_run_hdr::large_run_hdr(size_t _num_pages) {
  // node_t needs no initialization; the node is made
  num_pages = _num_pages;
}


/********************
 * Small Run Header *
 ********************/

small_run_hdr::small_run_hdr(arena_bin* _parent) {
  // node_t needs no initialization; the node is made
  parent = _parent;
  free_list = NULL; // There is no free list
  free_cells = parent->available_registrations;
}

void small_run_hdr::finalize() {
  // The first cell is offset from the header by the header size
  next = (size_t*)((byte*)this + SMALL_RUN_HDR_SIZE);//
}

void* small_run_hdr::malloc() {
  PRINT_TRACE("   Entering malloc at the small_run_hdr level (%zu).\n", (parent->object_size));
  PRINT_TRACE("    Before we take one, this run has %zu uses left.\n", free_cells);
  // We *really* shouldn't be asked if we have no free space - this is a cleanup error
  assert(free_cells > 0);
  byte* new_address = NULL; //What we're giving the user
  free_cells--; // We've lost a free cell!

  // If no space left, get us off the tree! We don't want any more allocations
  if (free_cells == 0) {
    // We're also a node_t, so ask the parent to remove us
    PRINT_TRACE("    ...removing filled page from bin.\n");
    parent->filled_run((node_t*)this);
  }

  if (free_list != NULL) {
    PRINT_TRACE("    We're going to take a cell off the free list.\n");
    // Grab the head of the free list
    new_address = (byte*)free_list;
    // Pop it off and chain the free pointer down
    free_list = (size_t*)*free_list;
    // Give the user the space
  } else {
    PRINT_TRACE("    No free list; we're using the 'next' pointer.\n");
    // OK, so we don't have a free list.
    // Get a new cell from the never-used pointer
    new_address = (byte*)next;
    // Bump up the never-used pointer for next time
    next = (size_t*)((byte*)next + parent->object_size);
  }
  PRINT_TRACE("    I got you an address: %p.\n", new_address);
  return (void*) new_address;
}

void small_run_hdr::free(void* ptr) {
  // All right. We need to add this cell to our free list, and write
  // a free list pointer to its address.
  *(size_t**)ptr = free_list; // Item at head of free list is written to this
  free_list = (size_t*)ptr; // free_list pointer bound to this
  free_cells++;
  if (free_cells == 1) {
    // This indicates we were full. We're not anymore, so mark us available.
    parent->run_available((node_t*)this);
  }
}