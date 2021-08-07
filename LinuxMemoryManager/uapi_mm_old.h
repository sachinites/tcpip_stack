/*
 * =====================================================================================
 *
 *       Filename:  uapi_mm.h
 *
 *    Description:  This Header file ocntains public APIs to be used by the application
 *
 *        Version:  1.0
 *        Created:  02/01/2020 10:00:27 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Juniper Networks (https://csepracticals.wixsite.com/csepracticals), sachinites@gmail.com
 *        Company:  Juniper Networks
 *
 *        This file is part of the Linux Memory Manager distribution (https://github.com/sachinites) 
 *        Copyright (c) 2019 Abhishek Sagar.
 *        This program is free software: you can redistribute it and/or modify it under the terms of the GNU General 
 *        Public License as published by the Free Software Foundation, version 3.
 *        
 *        This program is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *        General Public License for more details.
 *
 *        visit website : https://csepracticals.wixsite.com/csepracticals for more courses and projects
 *                                  
 * =====================================================================================
 */

#ifndef __UAPI_MM__
#define __UAPI_MM__

#include <stdint.h>

void *
xcalloc(char *struct_name, int units);

void
xfree(void *app_ptr);

/*Printing Functions*/
void mm_print_memory_usage();
void mm_print_block_usage();

/*Initialization Functions*/
void
mm_init();

/*Registration function*/
void
mm_instantiate_new_page_family(
        char *struct_name,
        uint32_t struct_size);

#define XCALLOC(units, struct_name) \
    (calloc(units, sizeof(struct_name)))

#define MM_REG_STRUCT(struct_name)  \
    (mm_instantiate_new_page_family(#struct_name, sizeof(struct_name)))

#define XFREE(ptr)  \
    free(ptr)

#endif /* __UAPI_MM__ */
