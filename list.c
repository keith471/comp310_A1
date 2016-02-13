#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "list.h"

#define MAX_LINE 100

Node* head = NULL;
Node* tail = NULL;

void push(pid_t pid, char *line) {
    if (head == NULL) {
        head = (Node*) malloc(sizeof(Node));
        tail = head;
    }
    else {
        tail->next = (Node*) malloc(sizeof(Node));
        tail = tail->next;
    }
    tail->line = malloc(MAX_LINE*sizeof(char));
    strcpy(tail->line, line);
    tail->pid = pid;
    tail->next = NULL;	// tail->next should always be null
}

int find(pid_t pid) {
    int i = 0;
    for (Node* it=head; it != NULL; it=it->next) {
        if (it->pid == pid) {
            return i;
        }
        i++;
    }
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
        free(delete->line);
        free(delete);
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
    free(delete->line);
    free(delete);
    
    if (it->next == NULL) {
        tail = it;
    }

    return 0;
}

void delAll() {
    Node* curr = head;
    // Continuously delete the first element in the list until there are no elements left
    while (curr != NULL) {
        curr = curr->next;
        del(0);
    }
}

pid_t getLast() {
    if (tail != NULL) {
        return tail->pid;
    } else {
        return -1;
    }
}

void showJobs() {
    Node *curr = head;
    while (curr != NULL) {
    	// WNOHANG causes waitpid to return immediately. 0 is returned if the child with
    	// given pid exists
        if (waitpid(curr->pid, NULL, WNOHANG) == 0) {
            printf("[%i] ", curr->pid);
            printf("%s", curr->line);
            curr = curr->next;
        } else {
            int index = find(curr->pid);
            curr = curr->next;	// Get the next node before deleting the current one
            if (index != -1) {
                del(index);
            }
        }
    }
}
