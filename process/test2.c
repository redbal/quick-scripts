#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
//#include <sys/ptrace.h>

#define MAX_SIZE 1024
#define ADDR_SIZE 256


int splitHeapAddr (char * heapAddr)
{
	char * search = "-";
	char * heapStart = strtok(heapAddr, search);
	char * heapEnd = strtok(NULL, search);
	//printf("HEAP START: %s \tHEAP END: %s\n", \
    // 	heapStart, heapEnd);
	long start = (long)heapStart;
	long end = (long)heapEnd;
	printf("HEAP addr math %ld - %ld = %ld \n\n", end, start, (end-start));
    return start;

}
/*
void findStrInHeap (int pid, char * heapStart, char * heapEnd, char * search)
=======
*/
char* getHeapStart (char* heapAddr)
{
	printf("HEAP ADDR: %s\n", heapAddr);
	char* search = "-";
	char* heapStart = strtok(heapAddr, search);
	char* heapEnd = strtok(NULL, search);
	printf("HEAP START: %s \tHEAP END: %s\n", \
    	heapStart, heapEnd);
	return heapStart;
}

void findStrInHeap (int pid, char * heapStart, int len, char * search)
{
	char* memFile = malloc(50);	
	sprintf(memFile, "/proc/%d/mem", pid);

	int fd_proc_mem = open(memFile, O_RDWR);
	if (fd_proc_mem == -1)
	{
		printf("Could not open %s\n", memFile);
		exit(1);
  	}

	char* buf = malloc(ADDR_SIZE);

	lseek(fd_proc_mem, (int)*heapStart, SEEK_SET);
	read (fd_proc_mem, buf, ADDR_SIZE);

	printf("String at %ld in process %d is:\n", heapStart, pid);
	printf("  %s\n", buf);

	printf("\nNow, this string is modified\n");
	strncpy(buf, "proc-2", ADDR_SIZE);

	lseek(fd_proc_mem, 260, SEEK_SET);
	if (write (fd_proc_mem, buf, ADDR_SIZE) == -1) 
	{
		printf("Error while writing\n");
		exit(1);
	}
}

char* findHeap (FILE* procFile)
{
	size_t len = 0;
	ssize_t read;
	char* line = NULL;
	char* heap = "[heap]";
	int heapHead = 0;
	char* heapAddr = NULL;

	while ((read = getline(&line, &len, procFile)) != -1) 
	{
		char * strS = strstr(line, heap);	
		if (strS) 
		{ 
			printf("STRSTR %s", strS);
    			printf("Retrieved line of length %zu:\n", read);
    			heapAddr = strtok(line, " ");
			return heapAddr;
		        //printf("HEAP ADDR %s\n", heapAddr);
		}
	}
	return heapAddr;	
}


void openProcFile (char* process)
{
	char fnameBuf[MAX_SIZE];
	printf("Processing %s...\n", process);
	snprintf(fnameBuf, MAX_SIZE, "/proc/%s/maps", process);
    FILE* pFile = fopen(fnameBuf, "r");

    if ((pFile == NULL))
    {	printf("ERROR with opening file\n\n"); }
 	else
	{
    	    char* heap = findHeap(pFile);
	    char* heapStart = getHeapStart(heap);
            char* heapStartHex;
            heapStartHex = malloc(strlen(heapStart)+5);
	    char* x = "aaaaa";

            strcpy(heapStartHex, x);
            strcat(heapStartHex, heapStart);
	    int bbb = (int)strtol(heapStartHex, NULL, 16);

		//printf("HEAP START string %s len: %d\n", heapStartHex, strlen(heapStartHex));
		//printf("HEAP START hex %0x len: %d\n", bbb, strlen(heapStartHex));
		//printf("HEAP START decimal %d len: %d\n", heapStartHex, strlen(heapStartHex));
	        findStrInHeap( atoi(process), heapStart, strlen(heapStart), x); 
	}
}


int main(int ac, char **av)
{
	char* str;
	char* t = NULL;
	printf("Looking for PID %s\n", av[1]);	
    openProcFile(av[1]);
    return (0);
}
