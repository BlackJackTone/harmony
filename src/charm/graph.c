#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARMONY_COMBINE
#include "graph.h"
#endif

#define new_alloc(t)	(t *) calloc(1, sizeof(t))

void graph_add(struct graph_t *graph, struct node *node) {
    node->id = graph->size;
    if (graph->size >= graph->alloc_size) {
        graph->alloc_size = (graph->alloc_size + 1) * 2;
        graph->nodes = realloc(graph->nodes, (graph->alloc_size * sizeof(struct node *)));
    }
    graph->nodes[graph->size++] = node;
}

static struct stack {
    struct stack *next;
    struct node *node;
} *stack;

static void kosaraju_visit(struct node *node) {
    if (node->visited) {
        return;
    }
    node->visited = true;

    for (struct edge *edge = node->fwd; edge != NULL; edge = edge->next) {
        kosaraju_visit(edge->node);
    }

    // Push node
    struct stack *s = new_alloc(struct stack);
    s->node = node;
    s->next = stack;
    stack = s;
}

static void kosaraju_assign(struct node *node, int component) {
    if (node->visited) {
        return;
    }
    node->visited = true;
    node->component = component;
    for (struct edge *edge = node->bwd; edge != NULL; edge = edge->next) {
        kosaraju_assign(edge->node, component);
    }
}

int graph_find_scc(struct graph_t *graph) {
    for (int i = 0; i < graph->size; i++) {
        kosaraju_visit(graph->nodes[i]);
    }

    // make sure all nodes are marked and on the stack
    // while at it clear all the visited flags
    int count = 0;
    for (struct stack *s = stack; s != NULL; s = s->next) {
        assert(s->node->visited);
        s->node->visited = false;
        count++;
    }
    assert(count == graph->size);

    count = 0;
    while (stack != NULL) {
        // Pop
        struct stack *top = stack;
        stack = top->next;
        struct node *next = top->node;
        free(top);

        if (!next->visited) {
            kosaraju_assign(next, count++);
        }
    }
    for (int i = 0; i < graph->size; i++) {
        assert(graph->nodes[i]->visited);
    }

    return count;
}

// For tracking data races
struct access_info *graph_ai_alloc(struct access_info **ai_free, int multiplicity, int atomic, int pc) {
    struct access_info *ai;

    if ((ai = *ai_free) == 0) {
        ai = calloc(1, sizeof(*ai));
    }
    else {
        *ai_free = ai->next;
    }
    ai->multiplicity = multiplicity;
    ai->atomic = atomic;
    ai->pc = pc;
    return ai;
}

void graph_check_for_data_race(
    struct node *node,
    struct minheap *warnings,
    struct values_t *values,
    struct access_info **ai_free
) {
    // TODO.  We're checking both if x and y conflict and y and x conflict for any two x and y
    for (struct edge *edge = node->fwd; edge != NULL; edge = edge->next) {
        for (struct access_info *ai = edge->ai; ai != NULL; ai = ai->next) {
            if (ai->indices != NULL) {
                assert(ai->n > 0);
                if (ai->multiplicity > 1 && !ai->load && ai->atomic == 0) {
                    struct failure *f = new_alloc(struct failure);
                    f->type = FAIL_RACE;
                    f->choice = node->choice;
                    f->node = node;
                    f->address = value_put_address(values, ai->indices, ai->n * sizeof(uint64_t));
                    minheap_insert(warnings, f);
                }
                else {
                    for (struct edge *edge2 = edge->next; edge2 != NULL; edge2 = edge2->next) {
                        for (struct access_info *ai2 = edge2->ai; ai2 != NULL; ai2 = ai2->next) {
                            if (ai2->indices != NULL && !(ai->load && ai2->load) &&
                                (ai->atomic == 0 || ai2->atomic == 0)) {
                                int min = ai->n < ai2->n ? ai->n : ai2->n;
                                assert(min > 0);
                                if (memcmp(ai->indices, ai2->indices,
                                           min * sizeof(uint64_t)) == 0) {
                                    struct failure *f = new_alloc(struct failure);
                                    f->type = FAIL_RACE;
                                    f->choice = node->choice;
                                    f->node = node;
                                    f->address = value_put_address(values, ai->indices, min * sizeof(uint64_t));
                                    minheap_insert(warnings, f);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Put access_info structs back on the free list
    for (struct edge *edge = node->fwd; edge != NULL; edge = edge->next) {
        struct access_info *ai = edge->ai;
        if (ai != NULL) {
            while (ai->next != NULL) {
                ai = ai->next;
            }
            ai->next = *ai_free;
            *ai_free = edge->ai;
            edge->ai = NULL;
        }
    }
}
