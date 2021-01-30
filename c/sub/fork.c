#include <stdlib.h>
#include <stdio.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <sys/ptrace.h> 
#include <string.h>

<<<<<<< HEAD
typedef struct myENV {
=======
typedef myENV;

typdef struct myEnvironment {
>>>>>>> 9aef523949d57dd96fda80b0d82b71fa5b6a22c6
    char * AA;
    int myCount;
} myENV;

void echoStatus(myENV key){
    printf("myENV: %p\n\n", &key);
    char *name2 = getenv("AAA");
    int name3 = 0;

    if ( name2 == NULL ) {
        printf("NULL ENV: %s\n\n", name2);
        int name3 = setenv("AAA", "YES", 1);
        printf("Establishing AAA %d\n", name3);
    }
    else {
        printf("NOT NULL ENV: %s\n\n", name2);
    }

    if ( name3 == 0 ){
        printf("GET ENV: %s\n", getenv("AAA"));
    }
}

int main() 
{ 
    // make two process which run same 
    // program after this instruction 
    int p_id;

    p_id = getpid();
    long p_trace = ptrace(PTRACE_TRACEME, p_id, NULL, NULL);

    printf("Hello world! %d %p %ld\n", p_id, p_id, p_trace); 

    myENV test = {"TEST", 1};   
    printf("\n\n");
    echoStatus(test);
    printf("\n\n");
 
    return 0; 
} 

