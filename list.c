#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include "helpers.h"
#include "list.h"

Node* head = NULL;
Node* tail = NULL;

void push(pid_t pid, char **args, int numargs) {
    if (head == NULL) {
        head = (Node*) malloc(sizeof(Node));
        tail = head;
    }
    else {
        tail->next = (Node*) malloc(sizeof(Node));
        tail = tail->next;
    }
    
    printf("sizeof(args) = %lu\n", sizeof(args));
    printf("sizeof(tail->args) before = %lu\n", sizeof(tail->args));
    printf("tail-args address before: %p\n", tail->args);
    memcpy(tail->args, args, numargs*sizeof(char *));
    printf("sizeof(tail->args) after = %lu\n", sizeof(tail->args));
    printf("tail-args address after: %p\n", tail->args);
    tail->args[numargs] = NULL;
    tail->pid = pid;
    tail->numargs = numargs;
    tail->next = NULL;
}

int find(pid_t pid) {
    int i = 0;
    for (Node* it=head; it != NULL; it=it->next) {
        if (it->pid == pid) {
            printf("process %i found at link %d\n", it->pid, i);
            return i;
        }
        i++;
    }
    printf("couldn't find process %i\n", pid);
    return -1;
}

int del(int index) {
    Node* delete;
    Node* it = head;

    if (head == NULL) {
        return -1;
    }

    if (index == 0) {
        delete = head;
        head = head->next;
        printf("sizeof(delete->args) = %lu\n", sizeof(delete->args));
        printf("delete->args address: %p\n", delete->args);
        //free(delete->args);
        //free(delete);
        return 0;
    }

    for (int i=0; i<(index-1); i++) {
        if (it->next == NULL) {
            return -1;
        }
        it = it->next;
    }

    delete = it->next;
    if (delete == NULL) {
        return -1;
    }

    it->next = delete->next;
    //free(delete->args);
    //free(delete);

    return 0;
}

pid_t getLast() {
    return tail->pid;
}

void showJobs() {
    Node *curr = head;
    int index = 0;
    while (curr != NULL) {
        printf("Here\n");
    	// WNOHANG causes waitpid to return immediately. 0 is returned if the child with
    	// given pid exists
        if (waitpid(curr->pid, NULL, WNOHANG) == 0) {
            printf("[%i] ", curr->pid);
            printCommand(curr->args, curr->numargs);
            curr = curr->next;
        } else {
            curr = curr->next;	// Get the next node before deleting the current one
            del(index);
        }
    }
}