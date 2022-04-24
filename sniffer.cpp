#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

using namespace std;

// potřeba u překladu použít flag -lpcap https://askubuntu.com/questions/582042/problem-linking-against-pcap-h
// základní sniffer https://www.tcpdump.org/pcap.html

/* Pomocná struktura pro uchování příznaků */
struct Flags
  {
    bool interface = true;
    std::string interface_arg;
    int port = -1;
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

std::string determine_filter(Flags *flags)
{
  std::string expression = "";

  if (flags->port != -1) // port je zadán
  {
    if (flags->tcp == true && flags->udp == true)
      expression = "(udp and port " + std::to_string(flags->port) + ") or (tcp and port " + std::to_string(flags->port) + ")"; // udp and port X OR tcp and port X
    else if (flags->tcp == true)
      expression = "(tcp and port " + std::to_string(flags->port) + ")";
    else if (flags->udp == true)
      expression = "(udp and port " + std::to_string(flags->port) + ")";
    else
      expression = "port " + std::to_string(flags->port);
  }
  else // port není zadán
  {
    if (flags->tcp == true && flags->udp == true)
      expression = "udp or tcp";
    else if (flags->tcp == true)
      expression = "tcp";
    else if (flags->udp == true)
      expression = "udp";
  }
  
  if (expression != "" && (flags->arp == true || flags->icmp == true))
    expression += " or ";
  
  if (flags->arp == true && flags->icmp == true)
      expression += "arp or icmp or icmp6";
    else if (flags->arp == true)
      expression += "arp";
    else if (flags->icmp == true)
      expression += "icmp or icmp6";

  if (expression == "")
  {
    printf ("Nezadaný žádný filtr\n");
    exit(0);
  }

  return expression;
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
          {"port",  required_argument, 0, 'p'},
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
            flags.port = atoi(optarg);
            break;

        case 't': // tcp
            flags.tcp = true;
            break;

        case 'u': // udp
            flags.udp = true;
            break;

        case 'a': // arp
            flags.arp = true;
            break;

        case 'c': // icmp
            flags.icmp = true;
            break;

        case 'n': // počet paketů
            flags.packetcount = atoi(optarg);
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
    printf ("Nepodařilo se otevřít dané rozhraní %s\n", flags.interface_arg.c_str());
    exit(0);
  }

  //-------------------------

  if (pcap_datalink(handle) != DLT_EN10MB)
  {
    printf ("Zařízení nepodporuje ethernetové hlavičky");
    exit(0);
  }

  struct bpf_program fp;		/* The compiled filter expression */
  std::string filter_exp = determine_filter(&flags); //determine_filter(&flags);	/* The filter expression */
  bpf_u_int32 mask;		/* The netmask of our sniffing device */
  bpf_u_int32 net;		/* The IP of our sniffing device */
  struct pcap_pkthdr header;
	const u_char *packet;

  if (pcap_lookupnet(flags.interface_arg.c_str(), &net, &mask, errbuf) == -1) // TODO: no chyba?
  {
    printf ("Pro dané rozhraní se nepodařilo získat síťovou masku\n");
    net = 0;
    mask = 0;
  }

  if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1)
  {
    printf ("Nepodařilo se zkompilovat filter\n");
    exit(0);
  }
  if (pcap_setfilter(handle, &fp) == -1)
  {
    printf ("Nepodařilo se aplikovat filter\n");
    exit(0);
  }

  

  
  // const struct sniff_ip *ip; /* The IP header */
  // const struct sniff_tcp *tcp; /* The TCP header */
  // const char *payload; /* Packet payload */

  // ethernet = (struct ether_header*)(packet);

  // ethernet->ether_type

  // ethernet.ether_type == ntohs(ETHERTYPE_ARP);
  
  // ether_arp


  const struct ether_header *ethernet; /* The ethernet header */

  std::string packInfo = "";

  for (int i = 0; i < flags.packetcount; i++)
  {
    packet = pcap_next(handle, &header);
    ethernet = (struct ether_header*)(packet);

    printf("Type: %04hx\n", ethernet->ether_type);

    // timestamp
    char res[32];
    struct tm * timeinfo;
    timeinfo = gmtime (&header.ts.tv_sec);
    strftime(res, sizeof(res), "%Y-%m-%dT%H:%M:%S", timeinfo);
    printf("%s.%ld +02:00\n", res, header.ts.tv_usec);

    printf ("src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
    printf ("dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
  
    if (ethernet->ether_type == ntohs(ETHERTYPE_ARP))
      printf("Je to arp!\n");
  }



	/* And close the session */
	pcap_close(handle);

}