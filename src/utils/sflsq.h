/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/
 
//---------------------------------------------------------------
// if you are thinking to use these for new code, please consider
// instead using STL containers which give you all this and much
// more.  :)
//---------------------------------------------------------------

/*
*  sflsq.h
*
*  Simple LIST, STACK, QUEUE DICTIONARY(LIST BASED)interface
*
*  All of these functions are based on lists, which use
*  the standard malloc.
*
*  Note that NODE_DATA can be redifined with the
*  define below.
*
*  Author: Marc Norton
*/
#ifndef SFLSQ_H
#define SFLSQ_H

/*
*  
*/
typedef void * NODE_DATA;

/*
*    Simple list,stack or queue NODE
*/ 
typedef struct sf_lnode
{
    struct sf_lnode *next;
    struct sf_lnode *prev;
    NODE_DATA ndata;
}
SF_QNODE,SF_SNODE,SF_LNODE;


/*
*	Integer Stack - uses an array from the subroutines stack
*/
typedef struct {
    unsigned *stack;
    unsigned nstack;
    unsigned n;
}
SF_ISTACK;
/*
*	Pointer Stack - uses an array from the subroutines stack
*/
typedef struct {
    void **stack;
    unsigned nstack;
    unsigned n;
}
SF_PSTACK;


/*
*  Simple Structure for Queue's, stacks, lists
*/ 
typedef struct sf_list
{
    SF_LNODE *head, *tail;  
    SF_LNODE *cur;  /* used for First/Next walking */
    unsigned count;
}
SF_QUEUE,SF_STACK,SF_LIST;



/*
*  Linked List Interface
*/ 
SF_LIST * sflist_new ( void ); 
void      sflist_init ( SF_LIST * s); 
int       sflist_add_tail ( SF_LIST* s, NODE_DATA ndata );
int       sflist_add_head ( SF_LIST* s, NODE_DATA ndata );
int       sflist_add_before ( SF_LIST* s, SF_LNODE * lnode, NODE_DATA ndata );
int       sflist_add_after ( SF_LIST* s, SF_LNODE * lnode, NODE_DATA ndata );
NODE_DATA sflist_remove_head ( SF_LIST * s);
NODE_DATA sflist_remove_tail ( SF_LIST * s); 
void      sflist_remove_node (SF_LIST * s, SF_LNODE * n, void (*free)(void*) );
int       sflist_count ( SF_LIST* s); 
NODE_DATA sflist_first( SF_LIST * s);
NODE_DATA sflist_next( SF_LIST * s);
SF_LNODE * sflist_first_node( SF_LIST * s );
SF_LNODE * sflist_next_node( SF_LIST * s );
NODE_DATA sflist_firstpos( SF_LIST * s, SF_LNODE ** v );
NODE_DATA sflist_nextpos ( SF_LIST * s, SF_LNODE ** v );
void      sflist_free ( SF_LIST * s); 
void      sflist_free_all( SF_LIST * s, void (*free)(void*) ); 
void sflist_static_free_all(SF_LIST *, void(*nfree)(void *));
void sflist_static_free(SF_LIST *);

/*
*   Stack Interface ( LIFO - Last in, First out ) 
*/
SF_STACK *sfstack_new ( void ); 
int       sfstack_add( SF_STACK* s, NODE_DATA ndata ); 
NODE_DATA sfstack_remove ( SF_STACK * s);
int       sfstack_count ( SF_STACK * s); 
void      sfstack_free ( SF_STACK * s); 
void      sfstack_free_all( SF_STACK* s, void (*free)(void*) ); 
void sfstack_static_free_all(SF_STACK *,void (*nfree)(void *));
void sfstack_static_free(SF_STACK *);

/*
*   Queue Interface ( FIFO - First in, First out ) 
*/
SF_QUEUE *sfqueue_new ( void ); 
int       sfqueue_add( SF_QUEUE * s, NODE_DATA ndata ); 
NODE_DATA sfqueue_remove ( SF_QUEUE * s);
int       sfqueue_count ( SF_QUEUE * s); 
void      sfqueue_free ( SF_QUEUE * s); 
void      sfqueue_free_all( SF_QUEUE* s, void (*free)(void*) ); 
void sfqueue_static_free_all(SF_QUEUE *,void (*nfree)(void *));
void sfqueue_static_free(SF_QUEUE *);

/*
* Performance Stack functions for Integer/Unsigned and Pointers, uses
* user provided array storage, perhaps from the program stack or a global.
* These are efficient, and use no memory functions.
*/
int sfistack_init( SF_ISTACK * s, unsigned * a,  unsigned n  );
int sfistack_push( SF_ISTACK *s, unsigned value);
int sfistack_pop(  SF_ISTACK *s, unsigned * value);

int sfpstack_init( SF_PSTACK * s, void ** a,  unsigned n  );
int sfpstack_push( SF_PSTACK *s, void * value);
int sfpstack_pop(  SF_PSTACK *s, void ** value);

#endif
