/*
 * =====================================================================================
 *
 *       Filename:  libcliid.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  Saturday 05 August 2017 11:33:29  IST
 *       Revision:  1.0
 *       Compiler:  gcc
 *
 *         Author:  Er. Abhishek Sagar, Networking Developer (AS), sachinites@gmail.com
 *        Company:  Brocade Communications(Jul 2012- Mar 2016), Current : Juniper Networks(Apr 2017 - Present)
 *
 * =====================================================================================
 */

#ifndef __LIBCLIID__
#define __LIBCLIID__

typedef enum{
    CONFIG_DISABLE,
    CONFIG_ENABLE,
    OPERATIONAL,
    MODE_UNKNOWN
} op_mode;

typedef enum{
    INT,
    STRING,
    IPV4,
    FLOAT,
    IPV6,
    BOOLEAN,
    INVALID,
    LEAF_MAX
} leaf_type_t;




#endif


