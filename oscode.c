#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "list.h"

#define MAX_LINE 100	// 100 characters for a line. This should be plenty
#define MAX_PATH 100
#define PATH_INCREMENT 10
#define HISTORY_SIZE 10
#define ERR_CMDS_SIZE 20
#define MAX_ARGS 20
#define EXECVP_FAIL 100
#define EXECVP_UNDEF_ERR 101

typedef enum {HISTORY, HISTACCESS, PWD, CD, JOBS, EXIT, FG, EXTERNAL} cmd_type;

typedef struct {
    int cmdnum;
    int error;
    cmd_type type;
    int bg;
    int redirectIdx;
    char *line;
    int numargs;
} cmdTuple;

cmdTuple *history[HISTORY_SIZE];
int err_cmds[ERR_CMDS_SIZE] = {0};
int errcount = 0;
int cmdcount = 1;
static int *erroneous_cmd_num;	// A shared variable

// Parses line into args and returns the number of arguments in the command
// Also determines if the command is meant to run in the background, if it is a redirect,
// and the general type of the command
int parseline(char *line, char *args[], int *background, cmd_type *type, int *redirectIdx) {

	int i = 0;
    char *token, *loc;
    
    char *linecpy = malloc(MAX_LINE*sizeof(char));
    strcpy(linecpy, line);
    
    // Check if background is specified..
    if ((loc = index(linecpy, '&')) != NULL) {
        *background = 1;
        *loc = ' ';
    } else
        *background = 0;

    while ((token = strsep(&linecpy, " \t\n")) != NULL) {
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
    
    free(linecpy);
    
    return i;
}

// Returns the command string entered by the user
char* getcmd(char *prompt) {
    int length;
    char *line = NULL;
    size_t linecap = 0;
	
    printf("%s", prompt);
    length = getline(&line, &linecap, stdin);

    if (length <= 0) {
        exit(-1);
    }
    
    return line;
}

// ERRONEOUS COMMAND HANDLING *************************************

int erroneousCmd(int cmdnum) {
    for (int i = 0; i < ERR_CMDS_SIZE; i++) {
        if (err_cmds[i] == cmdnum) {
            return 1;
        }
    }
    return 0;
}

void addToErrCmds(int cmdnum) {
    int insertIndex = errcount % ERR_CMDS_SIZE;
    err_cmds[insertIndex] = cmdnum;
}

// HISTORY *****************************************************

cmdTuple* getHistory(int cmd) {
    for (int i = 0; i < HISTORY_SIZE; i++) {
        if (history[i]->cmdnum == cmd) {
            return history[i];
        }
    }
    
    return NULL;
}

int updateHistory(int cmdnum) {
    for (int i = 0; i < HISTORY_SIZE; i++) {
        if (history[i]->cmdnum == cmdnum) {
            history[i]->error = 1;
            return 1;
        }
    }
    
    return 0;
}

void printHistory() {
	int i = 0;
	while ((history[i] != NULL) && i < 10) {
		printf("(%i) ", history[i]->cmdnum);
		printf("%s", history[i]->line);
		//printCommand(history[i].args, history[i].numargs);
		i++;
	}
	if (i == 0) {
		printf("Nothing in history\n");
	}
}

void delHistory(int index) {
    free(history[index]->line);
    free(history[index]);
}

void addToHistory(char *line, int cmdnum, cmd_type type, int bg, int redirectIdx) {
    int insertIndex = (cmdnum - 1) % HISTORY_SIZE;
    // Check if the history array is full. If so, then we are clearly overwriting an entry
    // and need to free the associated memory
    if (history[HISTORY_SIZE-1] != NULL) {
        delHistory(insertIndex);
    }
    cmdTuple *hist = malloc(sizeof(cmdTuple));
    hist->line = malloc(MAX_LINE*sizeof(char));
    hist->cmdnum = cmdnum;
    int err = 0;
    if (erroneousCmd(cmdnum)) {
        err = 1;
    }
    hist->error = err;
    hist->type = type;
    hist->bg = bg;
    hist->redirectIdx = redirectIdx;
    strcpy(hist->line, line);
    history[insertIndex] = hist;
}

// JOBS ******************************************************

void addToJobs(pid_t pid, char *line) {
    push(pid, line);
}

// CLEANUP ***************************************************

void cleanup(char *line) {
    printf("Cleaning up...\n");
    // Clear history
    for(int i = 0; i < HISTORY_SIZE; i++) {
        if (history[i] != NULL) {
            delHistory(i);
        }
    }
    
    // Clear jobs
    delAll();
    
    // Clear line
    free(line);
    
	// Unmap the shared variable
	munmap(erroneous_cmd_num, sizeof(*erroneous_cmd_num));
	
	printf("Done clean-up\n");
}

// RUNNING AND PROCESSING COMMANDS *********************************************************

int runCmd(char *line, char *args[], int numargs, int cmdcount, int bg, int redirectIdx) {

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
			
			close(1);	// Close stdout
			open(args[redirectIdx+1], O_WRONLY|O_CREAT, 0666);		// Rewire std out to the
																	// given file
			err = execvp(newargs[0], newargs);
			
			printf("Error: %s\n", strerror(errno));
		    printf("Exiting child process...\n");
			
			if (!bg) {
			    if (err == -1) {
		            exit(EXECVP_FAIL);		// Return error code EXECVP_FAIL
		        } else {
		            exit(EXECVP_UNDEF_ERR);	// Return error code EXECVP_UNDEF_ERR
		        }
			} else {
			    *erroneous_cmd_num = cmdcount;
			    kill(getppid(), SIGUSR1);	// Signal failed command to parent
			    exit(EXIT_FAILURE);			// Exit normally
			}	    
		    
		} else {
		    err = execvp(args[0], args);
		    
		    printf("Error: %s\n", strerror(errno));
		    printf("Exiting child process...\n");
		    
		    if (!bg) {
			    if (err == -1) {
		            exit(EXECVP_FAIL);
		        } else {
		            exit(EXECVP_UNDEF_ERR);
		        }
			} else {
			    *erroneous_cmd_num = cmdcount;
			    kill(getppid(), SIGUSR1);
			    exit(EXIT_FAILURE);
			}

		}
	} else {
		// Parent process
		if (!bg) {
			int status = 0;
			waitpid(childPID, &status, 0);
			int exit_status = WEXITSTATUS(status);	// Get the exit status of the child
			// If the child failed, then return 1, indicating that the command should not
			// be added to history
			if (exit_status == EXECVP_FAIL || exit_status == EXECVP_UNDEF_ERR) {
			    return 1;
			} else {
			    return 0;
			}
		} else {
			// Add background process to jobs
		    printf("Adding process %i to jobs\n", childPID);
		    addToJobs(childPID, line);
		    return 0;
		}
	}
}

void processCommand(char *line, int bg_override) {

    char *args[20];
    int bg;
    cmd_type type = EXTERNAL;
    int redirectIdx = -1;
    
    int numargs = parseline(line, args, &bg, &type, &redirectIdx);
    
    bg = (bg || bg_override);
    
    // Assume command will be successful (and thus we should save it to history)
    int saveToHistory = 1;
    
    if (type == HISTORY) {
        if (redirectIdx != -1) {
            printf("Redirection of the 'history' command is not implemented\n");
            printf("Printing history instead\n");
        }
        // Loop through history and print the number and command
        printHistory();
        saveToHistory = 0;	// We won't save history command to history
    } else if (type == HISTACCESS) {
		saveToHistory = 0;	// We don't want to save these commands to history
		cmdTuple *cmd = getHistory(atoi(args[0]));	// Look for the command in history
		if (cmd != NULL) {
			printf("re-executing following command from history: \n");
			// The command exists in history
			// Check to see if it was erroneous
			if (!cmd->error) {
				// Not erroneous
				// Print the command to be run to the screen
				printf("%s\n", cmd->line);

				// Recursively process the command
				processCommand(cmd->line, bg);
				
				return;	
			} else {
				printf("that command previously resulted in an error - please try another\n");
			}
		} else {
			printf("no command found in history\n");
		}
		        
    } else if (type == PWD) {
    
        size_t size = MAX_PATH;	// 100 bytes should be plenty for the path
        char *buf = (char *) malloc(size);	
        char *pwd = getcwd(buf, size);
        
        // If pwd is null, then it is likely that the buffer was not large enough
        // Try incrementing the size of the buffer. If still getting an error, then
        // it is likely that the error has to do with something other than the buffer.
        // Print an error message in this case.
        int i = 0;
        while (pwd == NULL && i < 10) {
            free(buf);
            size += PATH_INCREMENT;
            buf = malloc(size);
            pwd = getcwd(buf, size);
        }
        
        if (pwd == NULL) {
            printf("Error: could not print present working directory\n");
        } else {
            printf("%s\n", pwd);
        }
        
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
            printf("Error: %s\n", strerror(errno));
        } else {
            printf("Now in: %s\n", dir);
        }
    
    } else if (type == JOBS) {
        showJobs();
    } else if (type == FG) {
        // 1. Get process id of the job to move to the foreground
        pid_t procid;
        if (args[1] == NULL) {
            // No pid entered - bring latest background job to foreground
            procid = getLast();
            printf("Getting the latest process added to background...\n");
        } else {
            procid = atoi(args[1]);
            if (procid == 0) {
                printf("Error: invalid argument passed to fg: %s\n", args[1]);
                return;
            } else if (procid < 0) {
                printf("Error: process IDs must be positive\n");
                return;
            }
        }
        
        if (procid < 0) {
            printf("No background jobs\n");
        } else {
			// 2. See if process is still running and handle     
			kill(procid, 0);
			if (errno == ESRCH) {
				printf("Process %i has already terminated\n", procid);
			} else {
				int status = 0;
				waitpid(procid, &status, 0);
			}
        }
    } else if (type == EXIT) {
        cleanup(line);
        printf("Exiting...\n");
        exit(EXIT_SUCCESS);
    } else if (type == EXTERNAL) {
        int err = runCmd(line, args, numargs, cmdcount, bg, redirectIdx);
        if (err) {
            saveToHistory = 0;
        }
    }
    
    // Add the command to history
    if (saveToHistory) {
        addToHistory(line, cmdcount, type, bg, redirectIdx);
        cmdcount++;
    }  
}

// SIGNAL HANDLING ************************************************

void handle_SIGINT(int sig) {
    signal(SIGTSTP, handle_SIGINT);
    
    printf("\nSignal %d received\n", sig);
    printf("To exit, use 'exit'\n");
}

void handle_SIGUSR1(int sig) {
    signal(SIGUSR1, handle_SIGUSR1);
    
    // Get the command number of the command that failed
    int failedcmd = *erroneous_cmd_num;
        
    // Check if the command has already been added to history.
    // If so, update its err field.
    // Else, add it to err_cmds so that when the command is added to history, its err field
    // can be appropriately set
    if (!updateHistory(failedcmd)) {
        addToErrCmds(failedcmd);
    }    

}

// MAIN *********************************************************
int main() {
    
    // Set up signals and handling ****************
    void handle_SIGINT(int);
    void handle_SIGUSR1(int);
    
    signal(SIGINT, handle_SIGINT);		// Receive and handle CTRL-C
    signal(SIGUSR1, handle_SIGUSR1);	// Receive and handle SIGUSR1
    
    // Set up shared variable *****************
    erroneous_cmd_num = mmap(NULL, sizeof(*erroneous_cmd_num), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *erroneous_cmd_num = 0;

	// Loop until user exits ****************
    while (1) {
        
        char *line = getcmd("\n>>  ");	// Read a line from stdin
		
		processCommand(line, 0);	// Process the command
		
		free(line);	 // Free the line
	}     
}
