#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <string>
#include <iostream>

using namespace std;

// potřeba u překladu použít flag -lpcap https://askubuntu.com/questions/582042/problem-linking-against-pcap-h
// základní sniffer https://www.tcpdump.org/pcap.html

/* Pomocná struktura pro uchování příznaků */
struct Flags
  {
    bool interface = true;
    std::string interface_arg;
    bool port = false;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp = false;
    int packetcount = 0;
  };


/* Makro pro rozeznání optional argumentu převzané z https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/ */
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

/* Funkce pro vypsání dostupných rozhranní nebo pro kontrolu vloženého argumentu */
bool checkInt(Flags flags)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_if_t *interface;

  /* Nalezení a kontrola existence interface */
  if(pcap_findalldevs(&interface, errbuff) == PCAP_ERROR)
  {
    printf ("Nebyl nalezen žádný interface!\n");
    exit(0);
  }

  pcap_if_t *temp = interface; // pro vyčištění celého vázaného listu 

  /* Vypsání dostupných interface možností */
  if (flags.interface)
  {
    do
    {
      printf("\t%s\n", interface->name);
      interface = interface->next;
    } while (interface != NULL);

    pcap_freealldevs(temp);
    exit(0);
  }

  // Kontrola vloženého argumentu
  do
  {
    if (flags.interface_arg == interface->name) // pokud najde shodu, argument je správně
    {
      pcap_freealldevs(temp);
      return false;
    }
    interface = interface->next;
  } while (interface != NULL);

  pcap_freealldevs(temp);
  return true;
}

int main (int argc, char **argv)
{
  struct Flags flags;
  int c;

  /* Vstupní argumenty */
  while (1)
    {
      static struct option long_options[] =
        {
          {"interface", optional_argument, 0, 'i'},
          {"port",  no_argument,       0, 'p'},
          {"tcp",  no_argument, 0, 't'},
          {"udp",  no_argument, 0, 'u'},
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
              flags.interface = false;
              flags.interface_arg = optarg;
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

  if (checkInt(flags)) // výpis/kontrola rozhránní
  {
    printf ("Zadaný argument není platným rozhraním!\n");
    exit(0);
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  /* Vytváření sniffing session */
  handle = pcap_open_live(flags.interface_arg.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
  {
    printf ("Nepodařilo se otevřít dané rozhraní\n");
    exit(0);
  }

}