#ifndef MM_VALIDATOR_H
#define MM_VALIDATOR_H
/*
 * validator.h - 6.172 Malloc Validator
 *
 * Validates a malloc/free/realloc implementation.
 *
 * Copyright (c) 2010, R. Bryant and D. O'Hallaron, All rights reserved.
 * May not be used, modified, or copied without permission.
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "mdriver.h"
#include "memlib.h"
#include "validator.h"

/* Returns true if p is ALIGNMENT-byte aligned */
#if (__WORDSIZE == 64 )
#define IS_ALIGNED(p)  ((((uint64_t)(p)) % ALIGNMENT) == 0)
#else
#define IS_ALIGNED(p)  ((((uint32_t)(p)) % ALIGNMENT) == 0)
#endif

/*
 * IMPORTANT: this implementation returns 0 if there's an error
 *                                        1 if no errors
 */

/***************************
 * Range list data structure
 **************************/

/* Records the extent of each block's payload */
typedef struct range_t {
  char *lo;              /* low payload address */
  char *hi;              /* high payload address */
  struct range_t *next;  /* next list element */
} range_t;

/*****************************************************************
 * The following routines manipulate the range list, which keeps
 * track of the extent of every allocated block payload. We use the
 * range list to detect any overlapping allocated blocks.
 ****************************************************************/

/*
 * add_range - As directed by request opnum in trace tracenum,
 *     we've just called the student's malloc to allocate a block of
 *     size bytes at addr lo. After checking the block for correctness,
 *     we create a range struct for this block and add it to the range list.
 */
template <class Type>
static int add_range(Type *impl, range_t **ranges, char *lo, 
			int size, int tracenum, int opnum)
{
  char *hi = lo + size - 1;
  range_t * p = (range_t *)malloc(sizeof(range_t));

  /* You can use this as a buffer for writing messages with sprintf. */
  char msg[MAXLINE];

  assert(size > 0);

  /* Payload addresses must be ALIGNMENT-byte aligned */
  //We don't check whether hi address is aligned or not because we have no way of knowing what is the high address that has been passed to us
  if (!IS_ALIGNED(lo)) {
    int ret = sprintf(msg, "Low payload address %p is not aligned\n", lo);
    printf("%s", msg);
    return 0;
  }

  /* The payload must lie within the extent of the heap */
  if (lo <= mem_heap_lo()) {
    int ret = sprintf(msg, "Payload must lie within the extent of the heap; the low payload address is %p, and the heap's lo address is %lu\n", lo, mem_heap_lo());
    printf("%s", msg);
    return 0;
  }

  /* The payload must not overlap any other payloads */
  // Get the range in ranges
  range_t *range = *ranges;

  if (range == NULL) {
    p->lo = lo;
    p->hi = hi;
    p->next = NULL;
    *ranges = p;
  } else {

    range_t *prev = NULL;
    while (range != NULL) {

      /* The range in ranges and the current range don't overlap
       only in two cases:
       lo and hi addresses of the current range are
      1) smaller than lo and hi of the range
      2) larger than lo and hi of the range
      */

      if ((range->lo < lo && range->hi < hi) || (range->lo > lo && range->hi > hi)) {
        // The regions do not overlap
        prev = range;
        range = range->next;
      } else {
        // The regions overlap
        int ret = sprintf(msg, "The payload overlaps with some other payload\n");
      }
    }

    /* Everything looks OK, so remember the extent of this block by creating a
     * range struct and adding it the range list.
     */
    //range_t p = {.lo = lo, .hi = hi, .next = NULL};
    p->lo = lo;
    p->hi = hi;
    p->next = NULL;
    prev->next = p;
  }

  return 1;
}

/*
 * remove_range - Free the range record of block whose payload starts at lo
 */
static void remove_range(range_t **ranges, char *lo)
{
//  range_t **prevpp = ranges;

  /* Iterate the linked list until you find the range with a matching lo
   * payload and remove it.  Remember to properly handle the case where the
   * payload is in the first node, and to free the node after unlinking it.
   */

  range_t * curr = *ranges;

  // If the list of ranges is empty, there's nothing to find and remove
  if (curr == NULL) {
    return;
  }

  // We keep track of the curr and prev elements
  // to be able to unlink and relink nodes
  range_t *prev = NULL;
  while (curr != NULL) {
    if (curr->lo == lo) {
      // Match found, remove the node
      if (curr == *ranges) {
        // The address lo matches the head of the list
        // Set the head of the list to curr.next
        *ranges = curr->next;
        // Free the node after unlinking it
        free(curr);
        return;
      } else {
        // Unlink the curr node
        prev->next = curr->next;
        // Free the node after unlinking it
        free(curr);
      }
    } else {
      // No match found, continue
      prev = curr;
      curr = curr->next;
    }
  }
}

/*
 * clear_ranges - free all of the range records for a trace
 */
static void clear_ranges(range_t **ranges)
{
  range_t *p;
  range_t *pnext;

  for (p = *ranges; p != NULL; p = pnext) {
    pnext = p->next;
    free(p);
  }
  *ranges = NULL;
}

/*
 * eval_mm_valid - Check the malloc package for correctness
 */
template <class Type>
int eval_mm_valid(Type *impl, trace_t *trace, int tracenum)
{
  int i = 0;
  int index = 0;
  int size = 0;
  int oldsize = 0;
  char *newp = NULL;
  char *oldp = NULL;
  char *p = NULL;
  range_t *ranges = NULL;

  /* Reset the heap. */
  impl->reset_brk();

  /* Call the mm package's init function */
  if (impl->init() < 0) {
    malloc_error(tracenum, 0, "impl init failed.");
    return 0;
  }

  /* Interpret each operation in the trace in order */
  for (i = 0; i < trace->num_ops; i++) {
    index = trace->ops[i].index;
    size = trace->ops[i].size;

    switch (trace->ops[i].type) {

      case ALLOC: /* malloc */

        /* Call the student's malloc */
        if ((p = (char *) impl->malloc(size)) == NULL) {
          malloc_error(tracenum, i, "impl malloc failed.");
          return 0;
        }

        /*
         * Test the range of the new block for correctness and add it
         * to the range list if OK. The block must be  be aligned properly,
         * and must not overlap any currently allocated block.
         */
        if (add_range(impl, &ranges, p, size, tracenum, i) == 0)
          return 0;

        /* Fill the allocated region with some unique data that you can check
         * for if the region is copied via realloc.
         */
        assert(p != NULL);

        // prev range_t contains the most recently allocated range
        memset(p, 0xA5, size);

//        for (int ii=0; ii < oldsize; ii++) {
//          assert((*(newp + i) == 0xA5));
//        }
        /* Remember region */
        trace->blocks[index] = p;
        trace->block_sizes[index] = size;
        break;

      case REALLOC: /* realloc */

        /* Call the student's realloc */
        oldp = trace->blocks[index];
        if ((newp = (char *) impl->realloc(oldp, size)) == NULL) {
          malloc_error(tracenum, i, "impl realloc failed.");
          return 0;
        }

        /* Remove the old region from the range list */
        remove_range(&ranges, oldp);

        /* Check new block for correctness and add it to range list */
        if (add_range(impl, &ranges, newp, size, tracenum, i) == 0)
          return 0;

        /* Make sure that the new block contains the data from the old block,
         * and then fill in the new block with new data that you can use to
         * verify the block was copied if it is resized again.
         */
        oldsize = trace->block_sizes[index];
        if (size < oldsize)
          oldsize = size;

          for (int i=0; i < oldsize; i++) {
	    // printf("newp=%f\n", *(double *)(newp + i));
            if (*(newp + i) != (char)(0xA5)) {
              malloc_error(tracenum, i, "newly allocated memory has different content than the one before reallocation.");
              return 0;
            }
          }

        memset(newp, 0xA5, size);

        /* Remember region */
        trace->blocks[index] = newp;
        trace->block_sizes[index] = size;
        break;

      case FREE: /* free */

        /* Remove region from list and call student's free function */
        p = trace->blocks[index];
        remove_range(&ranges, p);
        impl->free(p);
        break;

      default:
        app_error("Nonexistent request type in eval_mm_valid");
    }

  }

  /* Free ranges allocated and reset the heap. */
  impl->reset_brk();
  clear_ranges(&ranges);

  /* As far as we know, this is a valid malloc package */
  return 1;
}
#endif /* MM_VALIDATOR_H */
