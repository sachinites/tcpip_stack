/* This file Implements -A <x> -B <y> functionality, similar to like grep -A <x> -B <y> functionality */

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ncurses.h>
#include "../cli_const.h"

#define CIRCULAR_BUFFER_MAX_SIZE  64

typedef struct circular_buffer_ {

    char *sth_buff[CIRCULAR_BUFFER_MAX_SIZE];
    uint16_t n_count;
    uint16_t head;
    uint16_t tail;
    uint16_t a, A;
    uint16_t b, B;
    int match_string_index;

} circular_buffer_t;

void 
circular_buffer_reset (circular_buffer_t *cbuffer) {

    int i;

    for (i = 0; i < CIRCULAR_BUFFER_MAX_SIZE; i++) {
        if (cbuffer->sth_buff[i]) {
            free(cbuffer->sth_buff[i]);
            cbuffer->sth_buff[i] = NULL;
        }
    }

    cbuffer->n_count = 0;
    cbuffer->head = 0;
    cbuffer->tail = 0;
    cbuffer->a = 0;
    cbuffer->b = 0;
    cbuffer->match_string_index = -1;
}

typedef struct ABmgr_ {

    uint16_t A;
    uint16_t B;
    circular_buffer_t *cbuffer;

} ABmgr_t;

ABmgr_t *
ABmgr_get_instance (uint16_t A, uint16_t B) {

    ABmgr_t *abmgr = (ABmgr_t *)calloc (1, sizeof (ABmgr_t));
    abmgr->A = A;
    abmgr->B = B;
    abmgr->cbuffer = (circular_buffer_t *)calloc (1, sizeof (circular_buffer_t));
    abmgr->cbuffer->A = A;
    abmgr->cbuffer->B = B;
    abmgr->cbuffer->match_string_index = -1;
    return abmgr;
}

void 
ABmgr_reset(ABmgr_t *abmgr) {

    circular_buffer_reset  (abmgr->cbuffer);
}

void 
ABmgr_destroy(ABmgr_t *abmgr) {
    
    circular_buffer_reset (abmgr->cbuffer);
    free(abmgr->cbuffer);
    free(abmgr);
}

bool 
ABmgr_is_printable (ABmgr_t *abmgr) {

    return (abmgr->cbuffer->match_string_index  != -1);
}


void 
ABmgr_print (ABmgr_t *abmgr, void (*printfn)(unsigned char*, int)) {

    int j;

    printw("\n");
    
    for (j = abmgr->cbuffer->tail; j != abmgr->cbuffer->head; j++) {

        if (j == CIRCULAR_BUFFER_MAX_SIZE) {
            j = 0;
        }
        
        if (j == abmgr->cbuffer->match_string_index)
            attron(COLOR_PAIR(PLAYER_PAIR));

        printfn((unsigned char *)abmgr->cbuffer->sth_buff[j], 
            strlen(abmgr->cbuffer->sth_buff[j]));

        if (j == abmgr->cbuffer->match_string_index)
            attroff(COLOR_PAIR(PLAYER_PAIR));
    }
}

uint32_t 
ABmgr_data_copy (ABmgr_t *abmgr,  char *buffer,  uint32_t bsize) {

    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t k = 0;

    for (i = abmgr->cbuffer->tail; i != abmgr->cbuffer->head; i++) {

        if (i == CIRCULAR_BUFFER_MAX_SIZE) i = 0;
        if (!abmgr->cbuffer->sth_buff[i]) continue;
        j = strlen(abmgr->cbuffer->sth_buff[i]);
        if ( (k + j) >= bsize ) break;
        strncpy (&buffer[k], abmgr->cbuffer->sth_buff[i], j );
        k += j;
    }
    
    return k;
}


/* If return true, then Cbuffer could be dumped */
bool
ABmgr_insert_string (ABmgr_t *abmgr, char *string, bool match) {

    if (abmgr->cbuffer->n_count == CIRCULAR_BUFFER_MAX_SIZE) assert (0);

    /* Inserting a matching string for the first time */
    if (abmgr->cbuffer->match_string_index == -1 && match) {

        abmgr->cbuffer->sth_buff[abmgr->cbuffer->head] = string;
        abmgr->cbuffer->match_string_index = abmgr->cbuffer->head;
        abmgr->cbuffer->head++;
        if (abmgr->cbuffer->head == CIRCULAR_BUFFER_MAX_SIZE) {
            abmgr->cbuffer->head = 0;
        }
        abmgr->cbuffer->n_count++;
        if  (abmgr->cbuffer->A == 0 && abmgr->cbuffer->B == 0) return true;
        if  (abmgr->cbuffer->a <= abmgr->cbuffer->A && abmgr->cbuffer->B == 0) return true;
        return false;
    }

    /* Inserting a non-matching string 
        Case A : When matching string is not yet seen 
        Case B : When matching string is already seen 
    */
   // Case A : 
    if (!match && abmgr->cbuffer->match_string_index == -1) {

        /* Dont store strings until the matching string is seen */
        if (abmgr->A == 0) return false;
       
        /* We have not yet inserted the matching string */
        abmgr->cbuffer->sth_buff[abmgr->cbuffer->head] = string;
        abmgr->cbuffer->head++;
        if (abmgr->cbuffer->head == CIRCULAR_BUFFER_MAX_SIZE) {
            abmgr->cbuffer->head = 0;
        }
        abmgr->cbuffer->n_count++;
        abmgr->cbuffer->a++;
        
        if (abmgr->cbuffer->a > abmgr->cbuffer->A) {
            abmgr->cbuffer->a--;
            abmgr->cbuffer->tail++;
            if (abmgr->cbuffer->tail == CIRCULAR_BUFFER_MAX_SIZE) {
                abmgr->cbuffer->tail = 0;
            }
            abmgr->cbuffer->n_count--;
        }
        return false;
    }

    // Case B: 
    if (!match && abmgr->cbuffer->match_string_index != -1) {

        abmgr->cbuffer->sth_buff[abmgr->cbuffer->head] = string;
        abmgr->cbuffer->head++;
        if (abmgr->cbuffer->head == CIRCULAR_BUFFER_MAX_SIZE) {
            abmgr->cbuffer->head = 0;
        }
        abmgr->cbuffer->n_count++;
        abmgr->cbuffer->b++;
        if (abmgr->cbuffer->b == abmgr->cbuffer->B) {
            return true;
        }
        return false;
    }

    // Inserting a matchig string again, treat it like non-matching string 
    if (match && abmgr->cbuffer->match_string_index != -1) {

        return ABmgr_insert_string (abmgr, string, false);
    }

    assert (0);
    return true;
}

#if 0
int 
main (int argc, char **argv) {

    char *string_set[] = {
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "2",
        "8",
        "9",
        "10"
    };

    ABmgr_t *abmgr = ABmgr_get_instance (0, 0);
    int i; 

    for (i = 0; i < 10; i++) {

        if (1 || strcmp(string_set[i], "2") == 0) {
            printf ("Inserting matching string : %s\n", string_set[i]);
            if (ABmgr_insert_string (abmgr, string_set[i], true)) {
                printf ("Dumping Cbuffer\n");
                int j;
                for (j = abmgr->cbuffer->tail; j != abmgr->cbuffer->head; j++) {
                    if (j == CIRCULAR_BUFFER_MAX_SIZE) {
                        j = 0;
                    }
                    printf ("%s ", abmgr->cbuffer->sth_buff[j]);
                }
                printf ("\n");
                ABmgr_reset(abmgr);
            }
        }
        else {
            printf ("Inserting non-matching string : %s\n", string_set[i]);
            if (ABmgr_insert_string (abmgr, string_set[i], false)) {
                printf ("Dumping Cbuffer\n");
                int j;
                for (j = abmgr->cbuffer->tail; j != abmgr->cbuffer->head; j++) {
                    if (j == CIRCULAR_BUFFER_MAX_SIZE) {
                        j = 0;
                    }
                    printf ("%s ", abmgr->cbuffer->sth_buff[j]);
                }
                printf ("\n");
                ABmgr_reset(abmgr);
            }
        }
    }


    ABmgr_destroy(abmgr);
    return 0;
}
#endif