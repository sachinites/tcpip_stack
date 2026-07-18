#include <stdio.h>
#include <assert.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include "BPlusTree.h"


typedef enum dtype_{
	
	DTYPE_STRING,
	DTYPE_INT,
	DTYPE_DOUBLE

} dtype_t;	

static
int bplus_tree_key_comp_fn( BPluskey_t *key_1, 
												BPluskey_t *key_2, 
												key_mdata_t *key_mdata, int size) {

    int i , rc;
    int dsize;
    int offset = 0;

    dtype_t dtype;

    if (!key_1 || !key_1->key || !key_1->key_size) return 1;
    if (!key_2 || !key_2->key || !key_2->key_size) return -1;

    char *key1 = (char *)key_1->key;
    char *key2 = (char *)key_2->key;

    for (i = 0; i < size ; i++) {

        dtype = (dtype_t)(key_mdata)[i].dtype;
        dsize = (key_mdata)[i].size;

        switch (dtype) {

            case DTYPE_STRING:
                rc = strncmp (key1 + offset, key2 + offset, dsize);
                if (rc < 0) return 1;
                if (rc > 0) return -1;
                offset += dsize;
                break;

            case  DTYPE_INT:
                {
                    int *n1 = (int *)(key1 + offset);
                    int *n2 = (int *)(key2 + offset);
                    if (*n1 < *n2) return 1;
                    if (*n1 > *n2) return -1;
                    offset += dsize;
                }
                break;

            case DTYPE_DOUBLE:
              {
                    double *n1 = (double *)(key1 + offset);
                    double*n2 = (double *)(key2 + offset);
                    if (*n1 < *n2) return 1;
                    if (*n1 > *n2) return -1;
                    offset += dsize;
                }
                break;

            default:
                break;
        }
    }
    return 0;
}

int 
main (int argc, char **argv) {

	int len;
	int choice;
	char discard_buff[2];
	BPlusTree_t tree;
	memset (&tree, 0, sizeof (tree));

    static key_mdata_t key_mdata[] = {  {DTYPE_STRING, 32} };

	BPlusTree_init (&tree, 
			bplus_tree_key_comp_fn,
			0,
			0,
			4, 
			0,
			key_mdata,
			(int) (sizeof(key_mdata) / sizeof (key_mdata[0])));

	/* Lets insert records in B+ Tree as follows : 
		<country name>    |     <capital city name>
		where country name is a key and capital city name is a record 
	*/
	while (1) {

		printf ("1. Insert\n");
		printf ("2. Delete\n");
		printf ("3. Update\n");
		printf ("4. Read\n");
		printf ("5. Destroy\n");
		printf ("6. Iterate over all Records\n");
		printf ("7. exit\n");

		scanf ("%d", &choice);

		// read \n and discard it
		fgets ( (char *)discard_buff, sizeof(discard_buff), stdin);
		fflush (stdin);

		switch (choice) {

			case 1:
			{
				BPluskey_t bpkey;
				/* Take a new key buffer from heap, because this buffer will
					going to be cache by B+ Tree internally */
				char *key_buffer = (char *)calloc (1, 32);
				/* Setup the key*/
				bpkey.key = (void *)key_buffer;
				bpkey.key_size = 32;
				/* Take Key Input from the user*/
				printf ("Insert Key : ");
				fgets ( key_buffer, bpkey.key_size, stdin);
				 // Remove trailing newline
				key_buffer[strcspn(key_buffer, "\n")] = '\0';
				/* Setup the value*/
				/* Take a new value buffer from heap, because this buffer will
					going to be cache by B+ Tree internally */				
				char *value_buffer = (char *)calloc (1, 32);
				/* Take Value Input from the user*/
				printf ("Insert Value : ");
				fgets ( value_buffer, 32, stdin);
				 // Remove trailing newline
				value_buffer[strcspn(value_buffer, "\n")] = '\0';
				/* Insert the key value pair in the B+ Tree*/
				BPlusTree_Insert (&tree, &bpkey, (void *)value_buffer);
				// Nothing to free anything 
			}
			break;

			case 2:
				{
					BPluskey_t bpkey;
					char key_buffer[32];
					/* Setup the key*/
					bpkey.key = (void *)key_buffer;
					bpkey.key_size = sizeof (key_buffer);
					/* Take Key Input from the user*/
					printf ("Delete Key ? : ");
					fgets ( key_buffer, bpkey.key_size, stdin);
					// Remove trailing newline
					key_buffer[strcspn(key_buffer, "\n")] = '\0';
					/* Delete the record for this key */
					BPlusTree_Delete (&tree, &bpkey);
				}
				break;
			
			case 3:
			{
				BPluskey_t bpkey;
				char key_buffer[32];
				/* Setup the key*/
				bpkey.key = (void *)key_buffer;
				bpkey.key_size = sizeof(key_buffer);
				/* Take Key Input from the user*/
				printf ("Insert Key for Update ? : ");
				fgets ( key_buffer, bpkey.key_size, stdin);
				 // Remove trailing newline
				key_buffer[strcspn(key_buffer, "\n")] = '\0';
				char *old_val_buff = (char *)BPlusTree_Query_Key(&tree, &bpkey);
				if (!old_val_buff) {
					printf ("Key not found\n");
					scanf("\n");
					break;
				}
				printf ("Old Value = %s\n", (char *)old_val_buff);
				/* Take Value Input from the user*/
				char *new_val_buff = (char *)calloc (1, 32);
				printf ("Insert new Value ? : ");
				fgets (new_val_buff, 32, stdin);
				 // Remove trailing newline
				new_val_buff[strcspn(new_val_buff, "\n")] = '\0';	

				/* It will free the old record value and put the new one*/
				BPlusTree_Modify (&tree, &bpkey, (void *)new_val_buff);
			}
			break;

		case 4:
			{
				BPluskey_t bpkey;
				char key_buffer[32];
				/* Setup the key*/
				bpkey.key = (void *)key_buffer;
				bpkey.key_size = sizeof(key_buffer);
				/* Take Key Input from the user*/
				printf ("Insert Key for Read ? : ");
				fgets ( key_buffer, bpkey.key_size, stdin);
				 // Remove trailing newline
				key_buffer[strcspn(key_buffer, "\n")] = '\0';
				char *val_buff = (char *)BPlusTree_Query_Key(&tree, &bpkey);
				if (!val_buff) {
					printf ("Key not found\n");
					scanf("\n");
					break;
				}
				printf ("Value = %s\n", (char *)val_buff);
			}
			break;

		case 5:
			{
				BPlusTree_Destroy (&tree);
				printf ("Successfully Destroyed the B+ Tree\n");
			}
			break;

		case 6:
			{
				BPluskey_t *bpkey; 
				void *rec;

				BPTREE_ITERATE_ALL_RECORDS_BEGIN((&tree), bpkey, rec) {

					printf ("Key = %s, Value = %s\n", (char *)bpkey->key, (char *)rec);

				} BPTREE_ITERATE_ALL_RECORDS_END((&tree), bpkey, rec) ;
	
			}
			break;

		default:
			exit(0);

		} // switch ends 
	
	}
	
	return 0;
}