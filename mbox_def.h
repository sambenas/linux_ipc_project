/*
	mbox_def.h

	This file contains definitions for the mailbox
	and message types that will be used in 
	project 1.

	Last modified 3/28/16
	Author: Samuel Benas

*/
#include <linux/spinlock.h>
#ifndef MBOX_H
#define MBOX_H

typedef struct mbox_msg mbox_msg;
typedef struct mbox mbox;

struct mbox_msg {
	unsigned char* msg;
	unsigned long length;
	mbox_msg* next;
};

struct mbox {
	mbox_msg* first;
	mbox_msg* last;
	unsigned long id_num;
	unsigned long msg_count;
	mbox* next;
};

//This is the head pointer to the list of mailboxes
static mbox* mbox_list = NULL; 
static long mbox_count = 0;

static DEFINE_SPINLOCK(xor_lock);

static void do_xor(unsigned char* msg, unsigned long key, unsigned long len);

#endif
