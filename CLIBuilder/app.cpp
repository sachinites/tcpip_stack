#include <stddef.h>
#include <ncurses.h>
#include "libcli.h"

int 
main (int argc, char **argv) {

    libcli_init ();
    cli_start_shell();
    return 0;
}
