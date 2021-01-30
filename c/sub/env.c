#include <stdlib.h>
#include <stdio.h> 

#define MAX_ARR 1024

char *myENV[MAX_ARR] = { "AAA", "BBB", "CCC", "DDD" };

void checkENV(char *my_env){
    if ( getenv(my_env) ){
        printf("ENV defined: %s\n\n", my_env);
    }
    else { printf("ENV not defined: %s\n\n", my_env);}
}

//int name3 = setenv("AAA", "YES", 1);

int main() 
{ 
    printf("Hello world! \n"); 
    for ( int i = 0; i < MAX_ARR; i++){
        if ( myENV[i])
        {
            printf("myENV[%d] %s\n", i, myENV[i]); 
            checkENV(myENV[i]);
        }
    }
    return 0; 
} 


