
/* ====================x================x=================== */
/* Internal Stack Implementation */

#include <assert.h>

#define MAX_STACK_SIZE 256

typedef struct stack{
    int top;
    void* slot[MAX_STACK_SIZE];
    int count_of_push;
    int count_of_pop;
}Stack_t;

static Stack_t*
get_new_stack(void);
static int push(Stack_t *stack, void *node);
static void* pop(Stack_t *stack);
static int isStackEmpty(Stack_t *stack);
static void free_stack(Stack_t *stack);
static void* StackGetTopElem(Stack_t *stack);

Stack_t*
get_new_stack(void)
{
    Stack_t *stack = (Stack_t *)calloc(1, sizeof(Stack_t));
    if(!stack)
        return NULL;
    memset(stack, 0, sizeof(Stack_t));
    stack->top = -1;
    stack->count_of_push = 0;
    stack->count_of_pop = 0;
    return stack;
}

void* 
StackGetTopElem(Stack_t *stack) {

    if(!stack || stack->top == -1)  return NULL;
    return stack->slot[stack->top];
}

int 
isStackEmpty(Stack_t *stack) {

    assert(stack);
    if (stack->top == -1) return 1;
    return 0;
}

void* 
pop(Stack_t *stack) {

    void *ret = NULL;
    if(!stack) return NULL;
    if(stack->top == -1) return NULL;
    ret = stack->slot[stack->top];
    stack->slot[stack->top] = NULL;
    stack->top--;
    stack->count_of_pop++;
    return ret;
}

int 
push(Stack_t *stack, void *node) {
    if(!stack || !node) return -1;
    if(stack->top < MAX_STACK_SIZE) {
        stack->top++;
        stack->slot[stack->top] = node;
        stack->count_of_push++;
        return 0;
     }
    return -1;
}

void
free_stack(Stack_t *stack)
{
    if(!stack) return;
    free(stack);
}

/* Internal Stack Implementation FINISHED*/
/* ====================x================x=================== */
