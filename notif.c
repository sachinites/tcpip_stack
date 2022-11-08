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
#include "LinuxMemoryManager/uapi_mm.h"
#include "EventDispatcher/event_dispatcher.h"

/* returns true if both are identical else return false.
 * if key is set, then comparison is done based on keys only.
 * if key is not set in either of them, then comparison is done
 * based on callbacks registered
 * */
static bool
nfce_compare(notif_chain_elem_t *nfce1,
			 notif_chain_elem_t *nfce2) {

	if (nfce1->is_key_set) {
		
		if (nfce2->is_key_set) {

			if (nfce1->key_size == nfce2->key_size) {

				if (memcmp(nfce1->key, nfce2->key, nfce1->key_size) == 0) {
					return true;
				}
				else {
					return false;
				}
			}
			else {
				return false;
			}
		}
		else {
			return false;
		}
	}
	else {

		if (nfce2->is_key_set) {
			return false;
		}
		else {

			/*both dont have keys set*/
			if ((nfce1->app_cb == nfce2->app_cb) &&
				(nfce1->pkt_trap_cb == nfce2->pkt_trap_cb)) {

				return true;
			}
			else {

				return false;
			}
		}		
	}
}

void
nfc_register_notif_chain(notif_chain_t *nfc,
					 notif_chain_elem_t *nfce){

	notif_chain_elem_t *new_nfce = XCALLOC(0, 1, notif_chain_elem_t);
	memcpy(new_nfce, nfce, sizeof(notif_chain_elem_t));
	init_glthread(&new_nfce->glue);
	glthread_add_next(&nfc->notif_chain_head, &new_nfce->glue);	
}

void
nfc_de_register_notif_chain(notif_chain_t *nfc,
					notif_chain_elem_t *nfce_template){

	glthread_t *curr;
	notif_chain_elem_t *nfce;

	ITERATE_GLTHREAD_BEGIN(&nfc->notif_chain_head, curr){

		nfce = glthread_glue_to_notif_chain_elem(curr);

		if (nfce_compare(nfce_template, nfce)) {
			remove_glthread(&nfce->glue);
			XFREE(nfce);
			return;
		}
	}ITERATE_GLTHREAD_END(&nfc->notif_chain_head, curr);
}

uint16_t
nfc_invoke_notif_chain(
					  event_dispatcher_t *ev_dis,
					   notif_chain_t *nfc,
					   void *arg, size_t arg_size,
					   char *key, size_t key_size){

	bool trap_pkt;
	glthread_t *curr;
	uint16_t count = 0;
	void *arg_copy;
	notif_chain_elem_t *nfce;

	assert(key_size <= MAX_NOTIF_KEY_SIZE);

	ITERATE_GLTHREAD_BEGIN(&nfc->notif_chain_head, curr){

		nfce = glthread_glue_to_notif_chain_elem(curr);

		/*  Honor the pkt trap callback first if present */
		if (nfce->pkt_trap_cb) {
			
			trap_pkt = nfce->pkt_trap_cb(key, key_size);

			if (trap_pkt) {

				if (nfc->preprocessing_fn_ptr) {
					nfc->preprocessing_fn_ptr(arg);
				}

				arg_copy = nfc->copy_arg_fn_ptr ? nfc->copy_arg_fn_ptr(arg) : arg;

				count++;

				if (!ev_dis)
				{
					nfce->app_cb(ev_dis, arg_copy, arg_size);
				}
				else
				{
					task_create_new_job(ev_dis, arg_copy, nfce->app_cb, TASK_ONE_SHOT, TASK_PRIORITY_MEDIUM);
				}
			}
			continue;
		}

		if (!(key && key_size && 
			 nfce->is_key_set && (key_size == nfce->key_size))){

			if (nfc->preprocessing_fn_ptr) {
				nfc->preprocessing_fn_ptr(arg);
			}
			
			arg_copy = nfc->copy_arg_fn_ptr ? nfc->copy_arg_fn_ptr(arg) : arg;

			count++;

			if (!ev_dis)
			{
				nfce->app_cb(ev_dis, arg_copy, arg_size);
			}
			else
			{
				task_create_new_job(ev_dis, arg_copy, nfce->app_cb, TASK_ONE_SHOT, TASK_PRIORITY_MEDIUM);
			}
		}
		else {
			
			if (memcmp(key, nfce->key, key_size) == 0) {

				if (nfc->preprocessing_fn_ptr) {
					nfc->preprocessing_fn_ptr(arg);
				}

				arg_copy = nfc->copy_arg_fn_ptr ? nfc->copy_arg_fn_ptr(arg) : arg;

				count++;

				if (!ev_dis)
				{
					nfce->app_cb(ev_dis, arg_copy, arg_size);
				}
				else
				{
					task_create_new_job(ev_dis, arg_copy, nfce->app_cb, TASK_ONE_SHOT, TASK_PRIORITY_MEDIUM);
				}
			}
		}
	}ITERATE_GLTHREAD_END(&nfc->notif_chain_head, curr);
	return count;
}

void
nfc_mem_init () {

	MM_REG_STRUCT(0, notif_chain_t);
	MM_REG_STRUCT(0, notif_chain_elem_t);
}
