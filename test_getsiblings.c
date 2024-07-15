#include "types.h"
#include "user.h"

int main() {

    int child1_pid = fork();    // Parent process creates the first child process
    if (child1_pid == 0) {      // make sure only the child process enters this block     
        sleep(100);             // delay to allow sibiling creation
        getsiblings();          // getsiblings() syscall
        exit(0);                // Exit status added (lab1-part3)
    }

    int child2_pid = fork();
    if (child2_pid == 0) {
        sleep(100);
        //getsiblings();
        exit(0);                // Exit status added (lab1-part3)
    }

    int child3_pid = fork();
    if (child3_pid == 0) {
        sleep(100);
        //getsiblings();
        exit(0);                // Exit status added (lab1-part3)
    }

    // Calling wait syscall ensures the parent process waits for 
    // all child processes to terminate, preventing zombie processes.
    int wait_status;
    wait(&wait_status);         // Exit status added (lab1-part4)
    wait(&wait_status);         // Exit status added (lab1-part4)
    wait(&wait_status);         // Exit status added (lab1-part4)

    exit(0);                    // Exit status added (lab1-part3)
}
