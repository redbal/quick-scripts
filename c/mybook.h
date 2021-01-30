typedef struct myBook {
    char title[50];
    char author[50];
    int isGood;
} *myBookPtr;

void print(myBook);
void printMem(myBook);

void print(myBookPtr one){
    printf("\nBOOK: %s \t%s \t%d\n", one->title, one->author, one->isGood);
}

void printMem(myBookPtr one){
    printf("\nBOOK: %p \t%p \t%p\n", one->title, one->author, one->isGood);
}