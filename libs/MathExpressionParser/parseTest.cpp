#include "ParserExport.h"

int 
main (int argc, char **argv) {
    
    pinst_t inst;
    memset (&inst, 0, sizeof (inst));

    pinst_init (&inst);
    parse_init (&inst);

    while (1) {


        fgets ((char *)inst.lex_buffer, sizeof (inst.lex_buffer), stdin);

        if (inst.lex_buffer[0] == '\n') {
            inst.lex_buffer[0] = 0;
            continue;
        }

        /* Now parse the buffer */
        while ( !feof (inst.yyin)) {

            token_code = cyylex (&inst);
            printf ("Token Code = %d, Token = %s, TokenLen = %d\n", 
                token_code, inst.lex_curr_token, inst.lex_curr_token_len);
        }

        fseek (inst.yyin, 0, SEEK_SET);
    }

    pinst_destroy (&inst);
    return 0;
}
