typedef struct _Node {
    pid_t pid;
    char *line;
    struct _Node* next;
} Node;

void push(pid_t pid, char *line);
int find(pid_t pid);
int del(int index);
void delAll();
pid_t getLast();
void showJobs();