#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "stack.h"

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

int isPresentinStack(Stack_t *stack, void *elem)
{
    if(!stack)  assert(0);
    if(isStackEmpty(stack))
        return 0;
    int i= 0;
    void *ptr = NULL;
    for(; i <= stack->top; i++)
    {
        ptr = stack->slot[i];
        if(ptr == elem)
            return 1;
    }
    return 0;
 }

void printStack(Stack_t *stack)
{
    if(!stack) assert(0);
    if(isStackEmpty(stack)) 
        printf("stack is empty\n");

    int i = 0;

    printf("stack content:\n");
    for(i = stack->top; i >=0  ; i--){
        
    }
    printf("stack->count_of_push = %d\n", stack->count_of_push);
    printf("stack->count_of_pop = %d\n", stack->count_of_pop);
    return;
}


int
reset_stack(Stack_t *stack)
{
    if(!stack)
        return 0;

    memset(stack, 0, sizeof(Stack_t));
    stack->top = -1;
    return 0;
}

int push(Stack_t *stack, void *node)
{
    if(!stack || !node)
        return -1;
    if(stack->top < MAX_STACK_SIZE)
    {
        stack->top++;
        stack->slot[stack->top] = node;
        stack->count_of_push++;
        return 0;
     }
        printf("\nstack already full\n");
        return -1;
}

int isStackEmpty(Stack_t *stack)
{
    
    assert(stack);
     
     if(stack->top == -1) {
        return 1;
     }

     return 0;
}

void* pop(Stack_t *stack)
{
    void *ret = NULL;
    if(!stack) {
        return NULL;
    }

    if(stack->top == -1)
    {
        return NULL;
    }

    ret = stack->slot[stack->top];
    stack->slot[stack->top] = NULL;
    stack->top--;
    stack->count_of_pop++;
    return ret;
}

void* StackGetTopElem(Stack_t *stack)
{
    if(!stack || stack->top == -1) {
        return NULL;
    }

    return stack->slot[stack->top];
}

void free_stack(Stack_t *stack)
{
    if(!stack) {
        return;
    }
    free(stack);
}
