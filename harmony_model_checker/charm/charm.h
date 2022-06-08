#ifndef SRC_CHARM_H
#define SRC_CHARM_H

#include "minheap.h"
#include "code.h"
#include "value.h"
#include "graph.h"

struct scc {
    struct scc *next;
    unsigned int start, finish;
};

struct global_t {
    struct code_t code;
    struct values_t values;
    struct graph_t graph;
    unsigned int todo;           // points into graph->nodes
    mutex_t todo_lock;           // to access the todo list
    mutex_t todo_wait;           // to wait for SCC tasks
    unsigned int nworkers;       // total number of threads
    unsigned int scc_nwaiting;   // # workers waiting for SCC work
    unsigned int ncomponents;    // to generate component identifiers
    struct minheap *failures;    // queue of "struct failure"  (TODO: make part of struct node "issues")
    hvalue_t *processes;         // list of contexts of processes
    unsigned int nprocesses;     // the number of processes in the list
    double lasttime;             // since last report printed
    bool dumpfirst;              // for json dumping
    struct dfa *dfa;             // for tracking correct behaviors
    unsigned int diameter;       // graph diameter
    bool phase2;                 // when model checking is done and graph analysis starts
    struct scc *scc_todo;        // SCC search
    bool run_direct;             // non-model-checked mode
};

#endif //SRC_CHARM_H
