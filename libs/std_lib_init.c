
int (*stdlib_printf)(const char *format, ...) = 0;

extern void 
std_lib_init (int (*_stdlib_printf)(const char *format, ...)) {

    stdlib_printf = _stdlib_printf;
}