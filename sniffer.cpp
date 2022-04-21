#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <string>

/* Makro pro rozeznání optional argumentu převzané z https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/ */
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

int
main (int argc, char **argv)
{
  bool interface = true;
  // bool port = false;
  // bool tcp = false;
  // bool udp = false;
  // bool arp = false;
  // bool icmp = false;
  // int packetcount = 0;

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
                interface = false;
              else
                interface = true;
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

    /* Vypsání dostupných interface možností */
    if (interface)
    {
      char errbuff[PCAP_ERRBUF_SIZE];
      pcap_if_t *interface;

      if(pcap_findalldevs(&interface, errbuff) == PCAP_ERROR)
      {
        printf ("Nebyl nalezen žádný interface!\n");
        exit(0);
      }

      do
      {
        printf("\t%s\n", interface->name);
        interface = interface->next;
      } while (interface != NULL);
    }

  exit (0);
}