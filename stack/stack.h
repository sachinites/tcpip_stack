#ifndef __STACK__
#define __STACK__

#define MAX_STACK_SIZE 32


typedef struct stack{
    int top;
    int padding_;  // Padding to align slot[] to 8-byte boundary
    void* slot[MAX_STACK_SIZE];
    int count_of_push;
    int count_of_pop;
} __attribute__((aligned(8))) Stack_t;

Stack_t*
get_new_stack(void);

int
reset_stack(Stack_t *stack);

int push(Stack_t *stack, void *node);

void* pop(Stack_t *stack);

void* StackGetTopElem(Stack_t *stack);
int isStackEmpty(Stack_t *stack);
void free_stack(Stack_t *stack);
int isPresentinStack(Stack_t *stack, void *elem);
void printStack(Stack_t *stack);

#endif 
