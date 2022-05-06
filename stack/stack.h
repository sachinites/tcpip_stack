#define MAX_STACK_SIZE 32


typedef struct stack{
    int top;
    void* slot[MAX_STACK_SIZE];
    int count_of_push;
    int count_of_pop;
}stack_t;

stack_t*
get_new_stack();

int
reset_stack(stack_t *stack);

int push(stack_t *stack, void *node);

void* pop(stack_t *stack);

void* getTopElem(stack_t *stack);
int isStackEmpty(stack_t *stack);
void free_stack(stack_t *stack);
int isPresentinStack(stack_t *stack, void *elem);
void printStack(stack_t *stack);
