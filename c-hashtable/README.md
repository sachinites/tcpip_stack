# C Hash Table

## Source code for a hash table data structure in C

This code is made available under the terms of the new BSD license. 

If you use this code, drop me an email. It's nice to feel useful occasionally.  
I promise not to sell your email address to Nigerian spam bandits. Thanks.  
Christopher Clark (firstname.lastname @ cl.cam.ac.uk), January 2005. 


## Defined functions

  * create_hashtable
  * hashtable_insert
  * hashtable_search
  * hashtable_remove
  * hashtable_count
  * hashtable_destroy


## Example of use
    
    
          struct hashtable  *h;
          struct some_key   *k;
          struct some_value *v;
    
          static unsigned int         hash_from_key_fn( void *k );
          static int                  keys_equal_fn ( void *key1, void *key2 );
    
          h = create_hashtable(16, hash_from_key_fn, keys_equal_fn);
    
          insert_key   = (struct some_key *) malloc(sizeof(struct some_key));
          retrieve_key = (struct some_key *) malloc(sizeof(struct some_key));
    
          v = (struct some_value *) malloc(sizeof(struct some_value));
    
          (You should initialise insert_key, retrieve_key and v here)
     
          if (! hashtable_insert(h,insert_key,v) )
          {     exit(-1);               }
    
          if (NULL == (found = hashtable_search(h,retrieve_key) ))
          {    printf("not found!");                  }
    
          if (NULL == (found = hashtable_remove(h,retrieve_key) ))
          {    printf("Not found\n");                 }
    
          hashtable_destroy(h,1); /* second arg indicates "free(value)" */
    


## Description

The table will increase in size as elements are added, to keep the ratio of elements to table size below a threshold. The table is sized by selecting a prime number of appropriate magnitude, to ensure best distribution of the contents. 

For improved type safety, macros have been defined and may be used to define type-safe(r) hashtable access functions, with methods specialized to take known key and value types as parameters. Example: Insert this at the start of your file: 
    
    
     DEFINE_HASHTABLE_INSERT(insert_some, struct some_key, struct some_value);
     DEFINE_HASHTABLE_SEARCH(search_some, struct some_key, struct some_value);
     DEFINE_HASHTABLE_REMOVE(remove_some, struct some_key, struct some_value);
    

This defines the functions `insert_some`, `search_some` and `remove_some`. These operate just like hashtable_insert etc., with the same parameters, but their function signatures have `struct some_key *` rather than `void *`, and hence can generate compile time errors if your program is supplying incorrect data as a key (and similarly for value).

Note that the hash and key equality functions passed to create_hashtable still take `void *` parameters instead of `some key *`. This shouldn't be a serious issue as they're only defined and passed once, and the other functions will ensure that only valid keys are supplied to them.

The cost for this checking is increased code size and runtime overhead - if performance is important, it may be worth switching back to the unsafe methods once your program has been debugged with the safe methods. 


## Iterator

The iterator is a simple one-way iterator over the hashtable contents, providing accessors for the the key and value at the current element. 
    
    
        /* Iterator constructor only returns a valid iterator if
         * the hashtable is not empty */
    
        if (hashtable_count(h) > 0)
        {
            itr = hashtable_iterator(h);
            do {
                k = hashtable_iterator_key(itr);
                v = hashtable_iterator_value(itr);
    
                /* here (k,v) are a valid (key, value) pair */
                /* We could call 'hashtable_remove(h,k)' - and this operation
                 * 'free's k and returns v.
                 * However, after the operation, the iterator is broken.
                 */
    
            } while (hashtable_iterator_advance(itr));
        }
        free(itr);
    
    


## Notes

You may find this (external) page of [hash functions for strings][1] helpful. Note that the hashtable includes a small section of code to protect against poor hash functions - it may be worthwhile removing this if you are sure you are using a good hash function.

If hashing strings, remember that `strcmp` is not a boolean comparison function directly suitable for `keys_equal_fn`.  


Archived copy of the original hashtable implementation, where table size is a power of two, rather than prime. [ hashtable_powers.c ]   


[Christopher Clark][2]  
Updated 11th January, 2005.

   [1]: http://www.cs.yorku.ca/~oz/hash.html
   [2]: http://www.cl.cam.ac.uk/~cwc22/

