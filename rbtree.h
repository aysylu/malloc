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
 * static node_t* tree_find_min(tree_t*)
 *    Find and return the minimum (smallest address) node in the tree.
 *    (Do not remove the node.)
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
		    
		    // Extract head node
#define tree_head(x) ((x)->rbt_root)
		    
		    // Find minimum node.
		    static node_t* tree_find_min(tree_t* inTree) {
		      //printf("Searching tree %p.\n", inTree);
		      //printf("...from root %p.\n", &(inTree->rbt_root));
		      node_t* ret = tree_head(inTree);
		      
		      // If tree is empty...
		      if (rbtn_left_get(node_t, link, ret) == rbtn_left_get(node_t, link, &inTree->rbt_nil))
			return NULL;
		      
		      //printf("...and I don't think the tree is empty.\n");
		      //printf("Nil node is %p.\n", &(inTree->rbt_nil));

		      ret = rbtn_left_get(node_t, link, ret);

		      //printf("Initial left lookup is %p.\n", ret);
		      while (rbtn_left_get(node_t, link, ret) != &(inTree->rbt_nil)) {
			//printf("Looking for min...\n");
			//printf("  %p", &(inTree->rbt_nil));
			//printf("  %p", rbtn_left_get(node_t, link, ret));
			ret = rbtn_left_get(node_t, link, ret);
		      }
		      return ret;
		    }
#endif /* RBTREE_HEADER_GUARD */
