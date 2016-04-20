/*  
	proj1_syscalls.c

	This file contains the system call
	implementation for the required sys calls in
	project 1.

	Last modified: 3/28/16
	Author:  Samuel Benas

*/


#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <asm/errno.h>
#include "mbox_def.h"

//Function used by the send message and receive message 
//functions in order to perform the xor cipher
//Defined in mbox_def.h
//static void do_xor(unsigned char* msg, unsigned long key, unsigned long len);

//A spinlock used to make sure only one process can access a mailbox at a time
//defined in mbox_def.h
//static spinlock_t xor_lock = SPIN_LOCK_UNLOCKED;


/*
	create_mbox_421
	id = the id number for the new mailbox

	Creates a mailbox with ID number id, if a
	mailbox with that id does not already exist.
	Returns 0 on success
*/
asmlinkage long sys_create_mbox_421(unsigned long id){

	//Returns -EINVAL if mailbox with id already exists
	mbox* itr = mbox_list;
	mbox* temp;
	while(itr != NULL){
		if(itr->id_num == id){
			return -EINVAL;
		}
		itr = itr->next;
	}

	//Locking so no process can try to read/write before mailbox
	//is finished being created
	spin_lock(&xor_lock);
	
	//Allocates memory for new mailbox in kernel
	temp = kmalloc(sizeof(mbox), GFP_KERNEL);

	if(temp == NULL){
		spin_unlock(&xor_lock);
		//printk("Unable to allocate new mbox\n");
		return -ENOMEM;
	}

	temp->first = NULL;

	temp->last = NULL;

	temp->id_num = id;

	temp->msg_count = 0;

	temp->next = mbox_list;
	
	mbox_list = temp;

	mbox_count++;
	
	spin_unlock(&xor_lock);	 
	return 0;
}


/*
	remove_mbox_421

	Removes a mailbox if it is empty
	id = ID number of mailbox to remove
	Returns 0.
*/
asmlinkage long sys_remove_mbox_421(unsigned long id){


	mbox* itr = mbox_list;
	mbox* prev = NULL;

	spin_lock(&xor_lock);

	//Loop through list to find ID	
	while(itr != NULL){

		if(itr->id_num == id){

			if(itr->msg_count == 0){

				//Set previous mbox to point to next
				if(prev != NULL){
				
					prev->next = itr->next;
				}
				
				//Free the mailbox, double check to
				//Make sure it is not null
				if(itr != NULL){
					kfree(itr);
				}

				mbox_count--;

				if(mbox_count <= 0){
					mbox_list = NULL;
				}	

				return 0;				

			} else {
				spin_unlock(&xor_lock);
				return -EINVAL;
			}
			
	
		}

		prev = itr;
		itr = itr->next;
	}

	spin_unlock(&xor_lock);
	return -EINVAL; //Case when mailbox with ID not found					
}


/*
	count_mbox_421
	Returns the number of mailboxes
*/
asmlinkage long sys_count_mbox_421(void){
	
	return mbox_count;

	/* dumb
	long count = 0;
	mbox* itr = mbox_list;
	while(itr != NULL){
		count++;
		itr = itr->next;
	}
	*/
	
	//return count;

}



/*
	list_mbox_421
	mbxes = a user space array of mailbox id's
	k = the maximum number of ID's to copy

	Copies up to k mailbox ID's from the kernel mailbox
	into the user space array

	returns the number of ID's copied over.
*/
asmlinkage long  sys_list_mbox_421(unsigned long *mbxes, unsigned long k){

	long count = 0;
	mbox* itr = mbox_list;
	unsigned long bytes_copied;

	while(itr != NULL && count < k){

		bytes_copied = copy_to_user(&mbxes[count], &(itr->id_num), sizeof(unsigned long));		

		count++;
		itr = itr->next;
	}

	 
	
	return count;
}



/*
	count_msg_421
	id = A mailbox id for which we want to count the number
	of messages.

	Returns the number of messages in mailbox id
*/
asmlinkage long sys_count_msg_421(unsigned long id){

	mbox* itr = mbox_list;

	while(itr != NULL){
		if(itr->id_num == id){
			return itr->msg_count;
		}
		itr = itr->next;
	}


	//If mailbox ID not found
	return -EINVAL;

}



/*
	do_xor
	msg = a pointer to an array of bytes in kernel memory
	key = the xor cipher key

	Performs the XOR cipher with a given key on a max of len
	bytes
*/
static void do_xor(unsigned char* msg, unsigned long key, unsigned long len){

	int count = 0, rem;	//Counts the number of bytes encoded and remaining to encode, respectively
	unsigned long a, b, c, d, enc, temp = 0; //For bit manipulation
	
	
	while(count < len){
	
		rem = len - count;
		
		//Get the first byte, and other bytes if applicable
		a = (unsigned long)msg[count];
		
		if(rem <= 1){
			b = 0;
		} else {
			b = (unsigned long)msg[count+1];
		}

		if(rem <= 2){
			c = 0;
		} else {
			c = (unsigned long)msg[count+2];
		}

		if(rem <= 3){
			d = 0;
		} else {
			d = (unsigned long)msg[count+3];
		}

		//Now doing some bit manipulation in order to
		//put the 4 bytes in the right place to XOR
		//with the 4 byte key
		
		a<<=24;
		b<<=16;
		c<<=8;
		//d is correct as-is

		temp = a + b + c + d;

		enc = temp ^ key;  //the XOR step
	
		//Now we extract each byte from the 4 byte long

		d = enc & 255;
		c = (enc & 65280) >> 8;
		b = (enc & 16711680) >> 16;
		a = enc >> 24;
		
		//Put the bytes back in their array
		msg[count] = (unsigned char)a;
		
		if(rem > 1){
			msg[count+1] = (unsigned char)b;
		}
		if(rem > 2){
			msg[count+2] = (unsigned char)c;
		}
		if(rem > 3){
			msg[count+3] = (unsigned char)d;
		}

		count += 4;
		temp = 0;


	}	

	return;

}




/*
	send_msg_421
	id = mailbox id number
	msg = character array in user space to put in mailbox
	n = the number of bytes(characters) to send
	key = the encryption key to use

	Creates a new message and attaches it to the end of 
	the list of messages in mailbox for ID.  Copies
	msg from user space to kernel space and performs
	the XOR cipher on it using the given key.

	Returns number of bytes stored, which should be equal
	to n.
*/
asmlinkage long sys_send_msg_421(unsigned long id, unsigned char* msg, unsigned long n, unsigned long key){

	unsigned char* in_kernel;
	unsigned long num_bytes;
	mbox* itr;
	mbox_msg* temp;

	//Obtain lock
	spin_lock(&xor_lock);
	

	//Allocated kernel buffer for message
	in_kernel = kmalloc((sizeof(unsigned char)*n), GFP_KERNEL);
	
	//Return 0 bytes if no memory available
	if(in_kernel == NULL){
		spin_unlock(&xor_lock);
		return -ENOMEM;
	}

	num_bytes = 0;

	itr = mbox_list;

	//Try to find our mailbox
	while(itr != NULL){

		//If this mailbox exists, add the message	
		if(itr->id_num == id){
			
			//Copy message to kernel space
			num_bytes = copy_from_user(in_kernel, msg, n);
			//printk("copy_from_user copied %li bytes\n", num_bytes);

			//Perform the XOR 
			//printk("send before xor: %.*s\n", num_bytes, in_kernel);

			do_xor(in_kernel, key, (n-num_bytes));

			//printk("send: after xor %.*s\n", num_bytes, in_kernel);

			//Allocate space for a message, return
			//0 bytes if out of memory
			temp = kmalloc(sizeof(mbox_msg), GFP_KERNEL);
			if(temp == NULL){
				spin_unlock(&xor_lock);
				return -ENOMEM;
			}


			temp->msg = in_kernel;
			temp->length = (n-num_bytes);
			temp->next = NULL;

			if(itr->first == NULL){
				//printk("send: inserting head with %d length\n", temp->length);
				itr->first = temp;
			}

			if(mbox_list->last != NULL)
				mbox_list->last->next = temp;

			mbox_list->last = temp;
			itr->msg_count++;

		}

	itr = itr->next;

	}


	spin_unlock(&xor_lock);
	return (n-num_bytes);
}


/*
	recv_msg_421
	id = mailbox ID number
	msg - unsigned char array in user space
	n = maximum number of bytes
	key = encryption key
	
	Finds the first message in mailbox with ID and performs
	the XOR cipher on it then copies it to user space.
	
	Returns number of bytes copied, which is less than or 
	equal to n.	
*/
asmlinkage long sys_recv_msg_421(unsigned long id, unsigned char* msg, unsigned long n, unsigned long key){

	mbox* itr = mbox_list;
	unsigned long not_copied = n;	
	unsigned long num_bytes = n;
	mbox_msg* temp;

	spin_lock(&xor_lock);
	//Find our mailbox
	while(itr != NULL){

		if(itr->id_num == id){
			
			//printk("recv: found mailbox\n");
	
			//If there are any messages
			if(itr->msg_count > 0){
				//printk("recv: exists a message of length%d\n", itr->first->length);

				temp = itr->first;

				//Perform the XOR
				//printk("recv before xor: %.*s\n", temp->length, temp->msg);
				do_xor(temp->msg, key, temp->length);
				//printk("recv after xor: %.*s\n", temp->length, temp->msg);

				
				itr->first = itr->first->next;
				itr->msg_count--;	
			
				if(itr->msg_count == 0)
					itr->last = NULL;

				//Find min between n and msg length
				if(temp->length < n)
					num_bytes = temp->length;

				//Attempt to copy to user space, then delete in kernel space
				//printk("recv: Attempting to copy %d bytes\n", num_bytes);
				not_copied = copy_to_user(msg, temp->msg, num_bytes);

				//Checking for not null just to be safe
				if(temp->msg != NULL)
					kfree(temp->msg);
			
				if(temp != NULL)
					kfree(temp);
			}
		}
		
		itr = itr->next;
	}

	spin_unlock(&xor_lock);
	//Return the number successfully copied
	return (num_bytes - not_copied);
}

//end
