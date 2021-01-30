#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_SIZE 1024
#define ADDR_SIZE 128

typedef unsigned char BYTE;

//function to convert string to byte array
void string2ByteArray(char* input, BYTE* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

int findHeap (FILE* procFile)
{
	size_t len = 0;
	ssize_t read;
	char* line = NULL;
	char* heap = "[heap]";
	int heapHead = 0;
	char* heapAddr = NULL;

	while ((read = getline(&line, &len, procFile)) != -1)
	{
		char* strS = strstr(line, heap);
		if (strS)
		{
			heapAddr = strtok(line, " ");
		    char* search = "-";
    		char* heapStart = strtok(heapAddr, search);
			char HS[17];
			strcpy(HS, "0x");
			strcat(HS, heapStart);

    		char* heapEnd = strtok(NULL, search);
			char HE[17];
			strcpy(HE, "0x");
			strcat(HE, heapEnd);
			long a = (long)strtol(HS, NULL, 0);
			printf("0x%x %i\n", a, a); 

//94472806928384

 			printf("CALCULATE %s - %s\n\n", HS, HE); 
			//int a = (int)strtol(HS, NULL, 16);
			long b = (long)strtol(HE, NULL, 0);
			long c = b -a;
			printf("===> %ld | %ld | %ld\n\n", a, b, c);
			hexDump(search, HE, c);
 			printf("CALCULATING [end] %ld - [start] %ld = %ld \n\n", b, a, c);
		
			return c;
		}
	}
	return heapHead;
}


void hexDump(char *desc, void *addr, int len) 
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}

void openMem (char* pid)
{
	char procFile[ADDR_SIZE];
	sprintf(procFile, "/proc/%s/maps", pid);
	printf("Opening.. %s\n", procFile);
	FILE* pFile = fopen(procFile, "r");
	int heapOffset = findHeap(pFile);
//	close(procFile);
	//printf("Heap address: %s \n\n", heapAddr);
		
//	char memFile[ADDR_SIZE];
//	sprintf(memFile, "/proc/%s/mem", pid);
//	printf("Opening... %s\n", memFile);
//	FILE* mFile = fopen(memFile, "rb");
//	
//	hexDump("0", mFile, 32);
//	int mFD = fileno(mFile);	
//
//	if ( mFile == NULL )
//	{
//		perror("Error with file");
//		exit(1);
//	}
//	else 
//	{ 
//		printf("Opened file: %s \t[%d] [%d]\n\n", 
//			memFile, mFD, heapOffset); 
//		char buf_r[MAX_SIZE];
//		size_t nread = pread(buf_r, 2, MAX_SIZE, mFile);;
//		printf("[size_t]\t[%d]\n", sizeof(size_t));
//		printf("[buf_r]\t[%d]\n", sizeof(buf_r));
//		printf("[%s] [%d]\n", buf_r, sizeof(buf_r));
//		
//		//	fread(buf_r, sizeof(buf_r) +1, 1, mFile);
//		//	pread(mFD, buf_r, sizeof(buf_r), heapOffset);
//		printf("Closed file: %s\n\n", *mFile); 
//		fclose(mFile);
//	}

}

int main(int ac, char **av)
{
	char* str;
	char* t = NULL;
	printf("Looking for PID %s\n", av[1]);	
    int len = strlen(av[2]);
    BYTE arr[len];
    int i;
    
    //converting string to BYTE[]
    string2ByteArray(av[2], arr);
    
    //printing
    printf("ascii_str: %s\n", av[2]);
    printf("byte array is...\n");
    for(i=0; i<len; i++);
    {
        printf("%c - %d\n", av[2][i], arr[i]);
    }
    printf("\n");



	printf("Looking for string %s\n", av[2]);	
    openMem(av[1]);
    return (0);
}

