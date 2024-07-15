#include "types.h"
#include "user.h"

int main(int argc, char *argv[])
{
    int exitWait(void);
    int waitNothing(void);

    printf(1, "\nlab#1\n");
    if (atoi(argv[1]) == 1)
        exitWait();  
    else if (atoi(argv[1]) == 2)
        waitNothing();
    // End of test
    // exit(0);
    return 0;
}


int waitNothing(void){
    int ret, exit_status = -1;
    ret = wait(&exit_status);
    printf(1, "%d %d\n", ret, exit_status);
    return 0;
}

int exitWait(void) {
    int pid, ret_pid, exit_status;
    int i;

    for (i = 0; i < 2; i++) {
        pid = fork();
        if (pid == 0) { // only the child executed this code
            if (i == 0){
                printf(1, "%d %d\n", getpid(), 0);
                exit(0);
            }
            else{
                printf(1, "%d %d\n" ,getpid(), -1);
                exit(-1);
            } 
        } else if (pid > 0) { // only the parent executes this code
            ret_pid = wait(&exit_status);
            printf(1, "%d+%d\n", ret_pid, exit_status);
        } else { // something went wrong with fork system call
            printf(2, "\nError using fork\n");
            exit(-1);
        }
    }
    return 0;
}