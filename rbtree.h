#ifndef RBTREE_HEADER_GUARD
#define RBTREE_HEADER_GUARD

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

#define RB_COMPACT
#include "rb.h"

/* This wraps the red-black tree implementation in freeBSD,
 * implemented by Jason Evans (jasone@freebsd.org).
 * The implementation is not ours. Most of the wrapper is.
 *
 * The structure is implemented with a combination of macros
 * and function definitions, but results in the following 
 * unified API:
 *
 * node_t    type of rb tree nodes
 * tree_t    type of rb tree itself

 * static void tree_new(tree_t*)
 *    Initialize a tree by address
 * static void tree_insert(tree_t*, node_t*) 
 *    Insert a node in the tree
 * static void tree_remove(tree_t*, node_t*)
 *    Remove a node from the tree
 * static node_t* tree_first(tree_t*)
 *    Find and return the minimum (smallest address) node in the tree.
 *    (Do not remove the node.)
 * static node_t tree_next(tree_t*, node_t*)
 *    Find and return the next larger node after the given node, or
 *    NULL if you're at the end of the tree.
 */

// RB node structure - just the pointers!
typedef struct node_s node_t;
struct node_s {
  rb_node(node_t) link;
};

// Node comparator - compares addresses
static int nodeCmp(node_t* a_node, node_t* a_other) {
  if (a_node < a_other) 
    return -1;
  else if (a_node > a_other)
    return 1;
  else
    return 0;
}

// Node type
typedef rbt(node_t) tree_t;
// Do macros
rb_gen(static, tree_, tree_t, node_t, link, nodeCmp);
		    
#endif /* RBTREE_HEADER_GUARD */
