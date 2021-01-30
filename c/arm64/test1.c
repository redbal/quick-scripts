#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int len(char *str)
{
	int i;
	for (i = 0; str[i]; i++)
        {}
	return (i);
}

int main(int ac, char **av)
{
	char *str;
	int i = 1;
	int p_id = getpid();
	if (ac == 2)
	{
		str = malloc(len(av[1]) + 1);
		strcpy(str, av[1]);
	}
	while (i)
	{
		printf("[%d] PID: [%d] %s - addr: %p\n", i, p_id, str, str);
		sleep(3);
		i++;
	}
	free(str);
	return (0);
}

