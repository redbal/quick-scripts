#include <stdio.h>

typedef struct myBook {
    char title[50];
    char author[50];
    int isGood;
} myBook;

void print(myBook *);
void printMem(myBook);

void print(myBook *one){
    printf("\n P BOOK: %s \t%s \t%d\n", one->title, one->author, one->isGood);
}

void printMem(myBook one){
    printf("\nBOOK: %p \t%p \t%p\n", one.title, one.author, one.isGood);
}

int main () 
{
    myBook test1 = {"one", "author", 1};
    myBook* testPtr = &test1;
   
    print(testPtr);
    printMem(test1);

    printf("\n\ntest1: %p\n\n", test1);

    printf("\n\ntestPtr: %p\n\n", testPtr);

    return 0;
}
