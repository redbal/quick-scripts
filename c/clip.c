/**
 * clip.c
 * to compile and link (on X11R7): cc -o clip clip.c -lX11
 * to compile and link (on X11R6): cc -o clip clip.c -L/usr/X11R6/lib{libsuffix} -I/usr/X11R6/include -lX11
 * where libsuffix is 32 or 64 or 128 ( I wish I will get a chance to compile on this architecture ) 
 * depending on your machine word size.
 */
#include <stdio.h>
#include <stdlib.h>

#include <X11/Xlib.h>

#define s_PRIMARY   "PRIMARY"
#define s_CLIPBOARD "CLIPBOARD"

static Atom get_atom(Display*, const char*);
static void print_stuff0(Display*, Atom);

int
main()
{
  Atom a_Primary, a_Clipboard;
  Display* display = NULL;
  char* display_name = NULL;
  char* window_name = NULL;
  Window win;

  if(!(display = XOpenDisplay(display_name)))
    {
      fprintf(stderr, "Error opening %s\n", XDisplayName(display_name));
      return 0;
    }
  else { printf("DISPLAY: %s\n", XDisplayName(display_name)); }

  a_Primary = get_atom(display, s_PRIMARY);
  a_Clipboard = get_atom(display, s_CLIPBOARD);
 

  print_stuff0(display, a_Primary);
  print_stuff0(display, a_Clipboard);

  XCloseDisplay(display);
}

void
print_stuff0(Display* display, Atom atom)
{
  Window win;
  char* window_name;
  char* atom_name;

  atom_name = XGetAtomName(display, atom);

  if((win = XGetSelectionOwner(display, atom)) != None)
    {

      XFetchName(display, win, &window_name);
      printf("\"%s\" (WM_NAME of 0x%lX) owns selection of \"%s\" atom.\n", window_name, win, atom_name);
      XFree(window_name);
    }
  else
      printf("No body owns selection \"%s\"\n", atom_name);

}

Atom 
get_atom(Display* display, const char* atom)
{
  Atom a;
  if((a = XInternAtom(display, atom, True)) == None)
    {
      fprintf(stderr, "Oops, \"%s\" atom doesn't exists.\n", atom);
      XCloseDisplay(display);
      exit(2);
    }

  return a;

}
