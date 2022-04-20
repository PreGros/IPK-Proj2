#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

/* Funkce pro rozeznání optional argumentu převzaná z https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/ */
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

int
main (int argc, char **argv)
{

    
  int c;

  while (1)
    {
      static struct option long_options[] =
        {
          {"interface", optional_argument, 0, 'i'},
          {"port",  no_argument,       0, 'p'},
          {"tcp",  no_argument, 0, 't'},
          {"udp",  optional_argument, 0, 'u'},
          {"arp",    no_argument, 0, 'a'},
          {"icmp",    no_argument, 0, 'c'},
          {0, 0, 0, 0}
        };
        
      int option_index = 0;

      c = getopt_long (argc, argv, "i::p:tun:",
                       long_options, &option_index);

      if (c == -1)
        break;

      switch (c)
        {
        case 'i': // interface
            if (OPTIONAL_ARGUMENT_IS_PRESENT)
            {
                printf ("Interface s argumentem\n");
            }
            else
            {
                printf ("Interface bez argumentu\n");
            }
            break;

        case 'p': // port
            printf ("Vypsal jsi port!\n");
            break;

        case 't': // tcp
            printf ("Vypsal jsi tcp!\n");
            break;

        case 'u': // udp
            printf ("Vypsal jsi udp!\n");
            break;

        case 'a': // arp
            printf ("Vypsal jsi arp!\n");
            break;

        case 'c': // icmp
            printf ("Vypsal jsi icmp!\n");
            break;

        case 'n': // počet paketů
            printf ("Vypsal jsi počet paketů!\n");
            break;

        default:
          abort ();
        }
    }

  exit (0);
}