/*
 * =====================================================================================
 *
 *       Filename:  notif.c
 *
 *    Description: This file implements Generaic Notif Chain structures definitions
 *
 *        Version:  1.0
 *        Created:  10/17/2020 01:56:00 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  ABHISHEK SAGAR (), sachinites@gmail.com
 *   Organization:  Juniper Networks
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "notif.h"

void
nfc_register_notif_chain(notif_chain_t *nfc,
					 notif_chain_elem_t *nfce){

	notif_chain_elem_t *new_nfce = calloc(1, sizeof(notif_chain_elem_t));
	memcpy(new_nfce, nfce, sizeof(notif_chain_elem_t));
	init_glthread(&new_nfce->glue);
	glthread_add_next(&nfc->notif_chain_head, &new_nfce->glue);	
}

void
nfc_invoke_notif_chain(notif_chain_t *nfc,
					   void *arg, size_t arg_size,
					   char *key, size_t key_size){

	glthread_t *curr;
	notif_chain_elem_t *nfce;

	assert(key_size <= MAX_NOTIF_KEY_SIZE);

	ITERATE_GLTHREAD_BEGIN(&nfc->notif_chain_head, curr){

		nfce = glthread_glue_to_notif_chain_elem(curr);

		if(!(key && key_size && 
			 nfce->is_key_set && (key_size == nfce->key_size))){
				
				nfce->app_cb(arg, arg_size);
		}
		else {
			
			if(memcmp(key, nfce->key, key_size) == 0) {

				nfce->app_cb(arg, arg_size);
			}
		}
	}ITERATE_GLTHREAD_END(&nfc->notif_chain_head, curr);
}

