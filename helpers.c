#include <stdio.h>
#include <stdlib.h>

void printCommand(char **args, int numargs) {
    int i;
	for (i = 0; i < numargs; i++) {
		printf("%s ", args[i]);
	}
	printf("\n");
}