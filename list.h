typedef struct _Node {
    pid_t pid;
    char *args[20];
    int numargs;
    struct _Node* next;
} Node;

void push(pid_t pid, char **args, int numargs);
int find(pid_t pid);
int del(int index);
pid_t getLast();
void showJobs();