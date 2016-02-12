#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include "helpers.h"
#include "list.h"

const int HISTORY_SIZE = 10;
const int MAX_ARGS = 20;

typedef enum {HISTORY, HISTACCESS, PWD, CD, JOBS, EXIT, FG, EXTERNAL} cmd_type;

typedef struct {
    int cmdnum;
    int error;
    cmd_type type;
    int bg;
    int redirectIdx;
    char *args[20];
    int numargs;
} cmdTuple;

cmdTuple history[HISTORY_SIZE];

int getcmd(char *prompt, char *args[], int *background, cmd_type *type, int *redirectIdx) {
    int length, i = 0;
    char *token, *loc;
    char *line = NULL;
    size_t linecap = 0;
	
    printf("%s", prompt);
    length = getline(&line, &linecap, stdin);

    if (length <= 0) {
        exit(-1);
    }

    // Check if background is specified..
    if ((loc = index(line, '&')) != NULL) {
        *background = 1;
        *loc = ' ';
    } else
        *background = 0;

    while ((token = strsep(&line, " \t\n")) != NULL) {
        for (int j = 0; j < strlen(token); j++)
            if (token[j] <= 32)
                token[j] = '\0';
        if (strlen(token) > 0) {
            // Change command type if necessary
            if (i == 0) {
                if (strcmp(token, "history") == 0)
                    *type = HISTORY;
                else if (strcmp(token, "cd") == 0)
                    *type = CD;
                else if (strcmp(token, "pwd") == 0)
                    *type = PWD;
                else if (strcmp(token, "jobs") == 0)
                    *type = JOBS;
                else if (strcmp(token, "fg") == 0)
                    *type = FG;
                else if (strcmp(token, "exit") == 0)
                    *type = EXIT;
            } else {
                // Check for redirectIdx
                if (strcmp(token, ">") == 0)
                    *redirectIdx = i;
            }
            args[i++] = token;
        }
    }
    // One final check of the command type
    if (i == 1 && (atoi(args[0]) > 0)) {
        *type = HISTACCESS;
    }
    
    args[i] = NULL;
    
    free(line);	// Free line

    return i;
}

void freecmd(char *args[20], int numargs) {
    for (int i = 0; i < numargs; i++) {
        free(args[i]);
    }
    
    free(args);
}

cmdTuple* getHistory(int cmd) {
    for (int i = 0; i < HISTORY_SIZE; i++) {
        if (history[i].cmdnum == cmd) {
            return &history[i];
        }
    }
    
    return NULL;
}

void addToHistory(int cmdnum, int err, cmd_type type, int bg, int redirectIdx, char **args, int numargs) {
    int insertIndex = (cmdnum - 1) % 10;
    cmdTuple hist;
    hist.cmdnum = cmdnum;
    hist.error = err;
    hist.type = type;
    hist.bg = bg;
    hist.redirectIdx = redirectIdx;
    // sizeof(args) will give you the size of the pointer. This is no good to us, so instead
    // we use sizeof(args[0]) * numargs
    memcpy(hist.args, args, numargs*sizeof(args[0]));
    hist.args[numargs] = NULL;	// null-terminate args array
    hist.numargs = numargs;
    history[insertIndex] = hist;
}

void addToJobs(pid_t pid, char **args, int numargs) {
    push(pid, args, numargs);
}

int runCmd(char *args[], int numargs, int cmdcount, int bg, int redirectIdx) {

    pid_t childPID;
	int err = 0;
	
	childPID = fork();
	if (childPID < 0) {
		fprintf(stderr, "The fork failed");
	} else if (childPID == 0) {
		// Child process
		// If redirectIdx != -1, then the output of all the commands should go elsewhere
		if (redirectIdx != -1) {
			char *newargs[20] = {0};	// Initialize newargs
			memcpy(newargs, args, redirectIdx*sizeof(args[0]));
			//newargs[redirectIdx] = NULL;
			
			close(1);	// Close stdout
			open(args[redirectIdx+1], O_WRONLY|O_CREAT, 0666);		// Rewire std out to the
																	// given file
			err = execvp(newargs[0], newargs);
			
			if (err == -1) {
		        printf("Error: %s\n", strerror(errno));
		        printf("Exiting child process...\n");
		        exit(EXIT_FAILURE);
		    }
		    
		} else {
		    err = execvp(args[0], args);
		    
		    if (err == -1) {
		        printf("Error: %s\n", strerror(errno));
		        printf("Exiting child process...\n");
		        exit(EXIT_FAILURE);
		    }
		}
	} else {
		// Parent process
		if (!bg) {
			int status = 0;
			waitpid(childPID, &status, 0);
		} else {
		    printf("Process ID: %i\n", childPID);
		    addToJobs(childPID, args, numargs);
		}
	}
	
	return err;

}

// Return values:
// 0 --> successful command; command added to history
// -1 --> command not added to history for whatever reason
// 1 --> exit the program
int processCommand(char **args, int numargs, int cmdcount, cmd_type type, int bg, int redirectIdx) {
    
    // Assume command will be successful
    int saveToHistory = 1;
    
    if (type == HISTORY) {
        // Loop through history and print the number and command
        int i = 0;
        while ((history[i].args[0] != NULL) && i < 10) {
            printf("(%i) ", history[i].cmdnum);
            printCommand(history[i].args, history[i].numargs);
            i++;
        }
        
    } else if (type == HISTACCESS) {
        // Look for the command in history
		cmdTuple *cmd = getHistory(atoi(args[0]));
		if (cmd != NULL) {
			printf("command found in history: ");
			// The command exists in history
			// Check to see if it was erroneous
			if (!cmd->error) {
				// Not erroneous
				// Print the command to be run to the screen
				int i;
				for (i = 0; i < cmd->numargs; i++) {
					printf("%s ", cmd->args[i]);
				}
				printf("\n");

				// Recursively process the command
				int result = processCommand(cmd->args, cmd->numargs, cmdcount, cmd->type, cmd->bg, cmd->redirectIdx);
				
				return result;	// Return the result of the recursive call to main	
			} else {
				printf("there is an error with that command - please try another\n");
			}
		} else {
			printf("no command found in history\n");
		}
		
		saveToHistory = 0;	// We don't want to save these commands to history
        
    } else if (type == PWD) {
    
        size_t size = 100;	// 100 bytes should be plenty for the path
        char *buf = (char *) malloc(size);	
        char *pwd = getcwd(buf, size);
        
        // If pwd is null, then it is likely that the buffer was not large enough
        // Try incrementing the buffer up to 10 times. If still getting an error, then
        // it is likely that the error has to do with something other than the buffer.
        // Print an error message in this case.
        int i = 0;
        while (pwd == NULL && i < 10) {
            free(buf);
            size += 10;
            buf = (char *) malloc(size);
            pwd = getcwd(buf, size);
        }
        
        if (pwd == NULL) {
            printf("Error: could not print present working directory\n");
        } else {
            printf("%s\n", pwd);
        }
        
        // Free buf
        free(buf);
    
    } else if (type == CD) {
        
        char *dir;
        
        if (numargs == 1) {
            // User only issued "cd" so change to home directory
            dir = getenv("HOME");
        } else {
            dir = args[1];
            if (strcmp(dir, "~") == 0) {
                dir = getenv("HOME");
            }
        }
        
        int result = chdir(dir);
        
        if (result == -1) {
            printf("Error\n");
        } else {
            printf("Changed directory to: %s\n", dir);
        }
    
    } else if (type == JOBS) {
        showJobs();
    } else if (type == FG) {
    
    } else if (type == EXIT) {
        return 1;	// Return 1 to main, causing the shell to exit
    } else if (type == EXTERNAL) {
    
        int result = runCmd(args, numargs, cmdcount, bg, redirectIdx);
        if (result == -1) {
            saveToHistory = 0;
        }
    }
    
    // Add the command to history
    if (saveToHistory) {
        addToHistory(cmdcount, 0, type, bg, redirectIdx, args, numargs);
        return 0;
    }
    
    return -1;
}

/*void handle_SIGTSTP(int sig) {
    signal(SIGTSTP, handle_SIGTSTP);
    
    printf("\nSignal %d received\n", sig);
    
    // Add process to jobs
}*/

void handle_SIGINT(int sig) {
    signal(SIGTSTP, handle_SIGINT);
    
    printf("\nSignal %d received\n", sig);
    printf("Exiting...\n");
    exit(EXIT_SUCCESS);
}

int main() {

    char *args[20];
    int bg;
    int redirectIdx;
    int cnt;
    int cmdcount = 1;
    cmd_type type;;
    int result = 0;
    
    //void handle_SIGTSTP(int);
    void handle_SIGINT(int);
    
    //signal(SIGTSTP, handle_SIGTSTP);	// Receive and handle CTRL-Z
    signal(SIGINT, handle_SIGINT);		// Receive and handle CTRL-C

    while (1) {
        
        type = EXTERNAL; 		// Assume commands are external by default
        redirectIdx = -1;		// Assume no redirection by default
        //args = malloc(MAX_ARGS*sizeof(char *));
        cnt = getcmd("\n>>  ", args, &bg, &type, &redirectIdx);
        
		// Print statements for testing *******************
		for (int i = 0; i < cnt; i++)
			printf("\nArg[%d] = %s", i, args[i]);
		if (bg)
			printf("\nBackground enabled..\n");
		else
			printf("\nBackground not enabled \n");
		printf("\n\n");
		// END TESTING *************************************
		
		result = processCommand(args, cnt, cmdcount, type, bg, redirectIdx);
		
		//freecmd(args, cnt);
		
		// Conditionally increment cmdcount based on return of processCommand
		if (result == 0) {
		    // We saved the command to history and thus should increment cmdcount
		    cmdcount++;
		} else if (result == 1) {
		    // Exit the program
		    break;
		}
				 
	}
		
	return 0;
     
}