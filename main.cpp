#include "mynet.h"
#include <arpa/inet.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test enp0s3\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("Ethernet\n");
    const struct myEthernet *myEtehr = reinterpret_cast<const struct myEthernet*>(packet);
    printf("dMac: ");
    for(int i=0; i<6; i++){
        printf("%02X%c",myEtehr->dMac[i],(i==5)?'\n':':');
    }
    printf("sMac: ");
    for(int i=0; i<6; i++){
        printf("%02X%c",myEtehr->sMac[i],(i==5)?'\n':':');
    }
    if(((myEtehr->etherType<<8)|(myEtehr->etherType>>8)) == 0x0800){printf("\nIPv4\n");}


    //packet+=14;
    const struct myIP *myIp = reinterpret_cast<const struct myIP*>(myEtehr->data);//packet);
    printf("sIP: %s\n",inet_ntoa(myIp->ip_src));
    printf("dIP: %s\n",inet_ntoa(myIp->ip_dst));

    if((myIp->ip_p)==0x06) {printf("\nTCP\n"); //packet +=20;
        const struct myTcphdr *myTcp = reinterpret_cast<const struct myTcphdr*>(myIp->data);//packet);
        printf("sPort: %d\n",ntohs(myTcp->tcp_sPort));
        printf("dPort: %d\n",ntohs(myTcp->tcp_dPort));

        int tcpLen = ntohs(myIp->len)-20-20;
        if(tcpLen>=1){
            printf("data : ");
            if(tcpLen<=10){
                for(int i=0; i<tcpLen; i++){
                    printf("%02x ",myTcp->data[i]);}
            }
            else{
                for(int i=0; i<10; i++){
                    printf("%02x ",myTcp->data[i]);}
            }
        }
    }
    else printf("\nothers\n");
    printf("\n\n");

  }

  pcap_close(handle);
  return 0;
}


