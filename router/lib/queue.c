#include "queue.h"
#include <stdlib.h>
#include <assert.h>

queue queue_create(void)
{
	queue q = malloc(sizeof(struct queue));
	q->head = q->tail = NULL;
	q->length = 0;
	return q;
}

int queue_empty(queue q)
{
	return q->head == NULL;
}

void queue_enq(queue q, void *element)
{
	if(queue_empty(q)) {
		q->head = q->tail = cons(element, NULL);
		q->length++;
	} else {
		q->tail->next = cons(element, NULL);
		q->tail = q->tail->next;
		q->length++;
	}
}

void *queue_deq(queue q)
{
	assert(!queue_empty(q));
	{
		void *temp = q->head->element;
		q->head = cdr_and_free(q->head);
		q->length--;
		return temp;
	}
}
