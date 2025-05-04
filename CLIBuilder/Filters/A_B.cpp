/* This file Implements -A <x> -B <y> functionality, similar to like grep -A <x> -B <y> functionality */

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ncurses.h>
#include "../string_util.h"
#include "../cli_const.h"

#define BYTE8ALIGN(n)   ((n + 7) & ~7)

typedef struct circular_buffer_ {

    typedef struct {
        char *str;
        uint16_t str_len; 
    } arr_t;

    arr_t *sth_buff;
    uint16_t n_count;
    uint16_t head;
    uint16_t tail;
    uint16_t max_size;

} circular_buffer_t;

void 
circular_buffer_reset (circular_buffer_t *cbuffer) {

    int i;

    for (i = 0; i < cbuffer->max_size; i++) {

        if (cbuffer->sth_buff[i].str) {
            free(cbuffer->sth_buff[i].str);
            cbuffer->sth_buff[i].str = NULL;
            cbuffer->sth_buff[i].str_len = 0;
        }
    }

    cbuffer->n_count = 0;
    cbuffer->head = 0;
    cbuffer->tail = 0;
}

static void 
circular_buffer_insert (circular_buffer_t *cbuffer, void *data, uint16_t data_len) {

    assert (cbuffer->n_count < cbuffer->max_size);
    cbuffer->sth_buff[cbuffer->head].str = (char *)data;
    cbuffer->sth_buff[cbuffer->head].str_len = data_len;
    cbuffer->n_count++;
    cbuffer->head++;
    if (cbuffer->head == cbuffer->max_size) {
        cbuffer->head = 0;
    }
}

static void *
circular_buffer_tail_remove (circular_buffer_t *cbuffer, uint16_t *data_len) {

    if (cbuffer->n_count == 0) return NULL;
    
    void *data = (void *)cbuffer->sth_buff[cbuffer->tail].str;
    if (data_len) *data_len = cbuffer->sth_buff[cbuffer->tail].str_len;

    cbuffer->sth_buff[cbuffer->tail].str = NULL;
    cbuffer->sth_buff[cbuffer->tail].str_len = 0;

    cbuffer->n_count--;
    cbuffer->tail++;

    if (cbuffer->tail == cbuffer->max_size) cbuffer->tail = 0;
    if (cbuffer->n_count == 0) assert (cbuffer->head == cbuffer->tail);
    
    return data;
}

typedef struct ABmgr_ {

    uint16_t a, A;
    uint16_t b, B;
    int match_string_index;
    circular_buffer_t *cbuffer;

} ABmgr_t;

ABmgr_t *
ABmgr_get_instance (uint16_t A, uint16_t B) {

    ABmgr_t *abmgr = (ABmgr_t *)calloc (1, sizeof (ABmgr_t));
    abmgr->A = A;
    abmgr->B = B;
    abmgr->match_string_index = -1;
    abmgr->cbuffer = (circular_buffer_t *)calloc (1, sizeof (circular_buffer_t));
    abmgr->cbuffer->max_size = (A + B + 1);
    abmgr->cbuffer->sth_buff = 
        (circular_buffer_t::arr_t *)calloc (((abmgr->cbuffer->max_size + 7) & ~7),  // 8B align
            sizeof (circular_buffer_t::arr_t));
    return abmgr;
}

void 
ABmgr_reset(ABmgr_t *abmgr) {

    circular_buffer_reset  (abmgr->cbuffer);
    abmgr->match_string_index = -1;
    abmgr->a = 0;
    abmgr->b = 0;
}

void 
ABmgr_destroy(ABmgr_t *abmgr) {
    
    circular_buffer_reset (abmgr->cbuffer);
    free(abmgr->cbuffer->sth_buff);
    free(abmgr->cbuffer);
    free(abmgr);
}

bool 
ABmgr_is_printable (ABmgr_t *abmgr) {

    return (abmgr->match_string_index  != -1);
}


void 
ABmgr_print (ABmgr_t *abmgr, void (*printfn)(unsigned char*, int)) {

    int i = abmgr->cbuffer->tail;

    if (abmgr->cbuffer->n_count == 0) return;

    do {

        if (i == abmgr->match_string_index) 
            attron(COLOR_PAIR(PLAYER_PAIR));

        printfn((unsigned char *)abmgr->cbuffer->sth_buff[i].str,
            abmgr->cbuffer->sth_buff[i].str_len);

        if (i == abmgr->match_string_index)
            attroff(COLOR_PAIR(PLAYER_PAIR));

        i++;
        if (i == abmgr->cbuffer->max_size) i = 0;
        
    } while (i != abmgr->cbuffer->head);

}

uint32_t 
ABmgr_data_copy (ABmgr_t *abmgr,  char *buffer,  uint32_t bsize) {

    uint32_t offset = 0;
    int i = abmgr->cbuffer->tail;

    if (abmgr->cbuffer->n_count == 0) return 0;

    do {

        if ((offset + abmgr->cbuffer->sth_buff[i].str_len) > bsize) {
            assert(0);
        }

        memcpy (buffer + offset, abmgr->cbuffer->sth_buff[i].str,
            abmgr->cbuffer->sth_buff[i].str_len);
        offset += abmgr->cbuffer->sth_buff[i].str_len;

        i++;
        if (i == abmgr->cbuffer->max_size)  i = 0;
        
    } while (i != abmgr->cbuffer->head);

    return (uint32_t)offset;
}


/* If return true, then Cbuffer could be dumped */
bool
ABmgr_insert_string (ABmgr_t *abmgr, char *string, uint16_t msg_len, bool match, bool calloc_str) {

    assert (string && msg_len);

    /* Inserting a matching string for the first time */
    if (abmgr->match_string_index == -1 && match) {
        uint16_t curr_head = abmgr->cbuffer->head;
        if (calloc_str) string = stringdup (string, msg_len);
        circular_buffer_insert (abmgr->cbuffer, (void *)string, msg_len);
        abmgr->match_string_index = curr_head;
        if  (abmgr->A == 0 && abmgr->B == 0) return true;
        if  (abmgr->a <= abmgr->A && abmgr->B == 0) return true;
        return false;
    }

    /* Inserting a non-matching string 
        Case A : When matching string is not yet seen 
        Case B : When matching string is already seen 
    */
   // Case A : 
    if (!match && abmgr->match_string_index == -1) {

        /* Dont store strings until the matching string is seen */
        if (abmgr->A == 0) return false;
       
        /* We have not yet inserted the matching string */
        if (calloc_str) string = stringdup (string, msg_len);
        circular_buffer_insert (abmgr->cbuffer, (void *)string, msg_len);
        abmgr->a++;
        
        if (abmgr->a > abmgr->A) {
            abmgr->a--;
            free (circular_buffer_tail_remove  (abmgr->cbuffer, 0));
        }

        return false;
    }

    // Case B: 
    if (!match && abmgr->match_string_index != -1) {

        if (calloc_str) string = stringdup (string, msg_len);
        circular_buffer_insert (abmgr->cbuffer, (void *)string, msg_len);
        abmgr->b++;
        if (abmgr->b == abmgr->B) {
            return true;
        }
        return false;
    }

    // Inserting a matchig string again, treat it like non-matching string 
    if (match && abmgr->match_string_index != -1) {
        return ABmgr_insert_string (abmgr, string, msg_len, false, calloc_str);
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
            if (ABmgr_insert_string (abmgr, string_set[i], strlen (string_set[i]), true)) {
                printf ("Dumping Cbuffer\n");
                int j;
                for (j = abmgr->cbuffer->tail; j != abmgr->cbuffer->head; j++) {
                    if (j == abmgr->cbuffer->max_size) {
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
            if (ABmgr_insert_string (abmgr, string_set[i], strlen (string_set[i]), false)) {
                printf ("Dumping Cbuffer\n");
                int j;
                for (j = abmgr->cbuffer->tail; j != abmgr->cbuffer->head; j++) {
                    if (j ==  abmgr->cbuffer->max_size) {
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