#include <stdio.h>
#include <stdint.h>

#define MAX_CNT 10000

int
main (int agc, char **argv) {

    uint32_t count = 0;
    uint32_t i , j;

    for (i = 0; i <= 255; i++) {

        for (j = 0; j <= 255; j++) {

            printf (":CMD: conf node H6 route 100.1.%u.%u 32\n", i, j);
            count++;
            if (count == MAX_CNT) break;
        }
        if (count == MAX_CNT) break;
    }

     printf (":CMD: conf node H6 prefix-list pref1 permit 0 100.1.0.0 16 ge 16 le 32\n");
     printf (":CMD: conf node H6 protocol isis\n");
     printf (":CMD: conf node H6 protocol isis export-policy pref1\n");
     return 0;
}