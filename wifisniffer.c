#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>



u_int8_t chanell=1;
long long old_time=0;

struct radiotap_header {
	u_int8_t	version;
	u_int8_t	pad;
	u_int16_t	len;
	u_int32_t present;
	u_int32_t present2;//mt7601
	u_int8_t	flag;
	u_int8_t	datarate;
	u_int16_t	chanell;
	u_int16_t	chanellflag;
	int8_t signal;



};


struct ieee802_11_header {
	u_int16_t	f_ctrl;
	u_int16_t	dur;
	u_int8_t	addr1[6];
	u_int8_t	addr2[6];
	u_int8_t	addr3[6];
	u_int16_t	seq;
	u_int8_t	addr4[6];
	u_int8_t	bssid[6];
	u_int8_t	sta[6];
};

struct random_mac {
	char	    ssid[20];
	u_int8_t	addr1[6];
};

struct mac_base {
		u_int8_t	randomMAC[6];
};

struct settings {
		char ip[16];
		char chanel[2];
		char mode[1];
		char mac[23]
		 
};

static void MDString ();



char* errbuf;
pcap_t* handle;


struct OUI
{
    __uint32_t code;
    char name[20];
};
struct settings settings;
struct OUI masVendor[28870];
struct OUI masPriorytyVendor[5000];
struct random_mac masSSID[256];
struct mac_base macBase[1];
u_int8_t countSSID=0;//count add ssid
u_int8_t countMAC=0;//count ass mac
u_int8_t flagSSD=1;
__uint32_t hexNumb=0;
char nameVendor[20];

///////////////////
int cp1251(char i)
{
if(i<=9)
return 0x30+i;
else
return 0x57+i;

}


//////////Get manufactory


////get mac raps

int GetMacRaps()
{
struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, "ens33");
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
 	sprintf(settings.mac,"%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) s.ifr_addr.sa_data[0],(unsigned char) s.ifr_addr.sa_data[1],(unsigned char) s.ifr_addr.sa_data[2],(unsigned char) s.ifr_addr.sa_data[3],(unsigned char) s.ifr_addr.sa_data[4],(unsigned char) s.ifr_addr.sa_data[5]);
   settings.mac[17]=0;
    return 1;
  }
  return 0;



}



//

char* getOui(int ouCode)
{
int i=0;
while (masVendor[i].code!=0x0)
{
   if(masVendor[i].code==ouCode)
   {
       return masVendor[i].name;
       break;
   }
   i++;
   if (masVendor[i].code==0x0)
   {
  
   return "unknown";

   } 
}

}

///getPriorityVendor
int getOuiPriority(int ouCode)
{
int i=0;
while (masPriorytyVendor[i].code!=0x0)
{
   if(masPriorytyVendor[i].code==ouCode)
   {
       return 1;
       break;
   }
   i++;
   if (masPriorytyVendor[i].code==0x0)
   {
  
   return 0;

   } 
}

}

/////////////

///////////////////////////////////////////////Read OIU file
void readOUI()
{
FILE *mf;
char str[50];


// Открытие файла с режимом доступа «только чтение» и привязка к нему 
   // потока данных

   mf = fopen ("oui_vendor","r");

    // Проверка открытия файла
   if (mf == NULL) {printf ("ошибка\n");}
   //else printf ("Vendor OUI file OK\n");


  //Чтение (построчно) данных из файла в бесконечном цикле
  int lenOUI=0;
   while (1)
   {
     
      if(fscanf(mf,"%x %s",&masVendor[lenOUI].code,masVendor[lenOUI].name )==2)
      lenOUI++; 
      else 
      break;
   }
  
   if ( fclose (mf) == EOF) printf ("Error close file\n");
 //  else printf ("ReadFileOUI OK: %d\n",lenOUI);
}


///////////////////////////////////////////

void readOUI_Priority()
{
FILE *mf;
char str[50];


// Открытие файла с режимом доступа «только чтение» и привязка к нему 
   // потока данных

   mf = fopen ("pr_vendor","r");

    // Проверка открытия файла
   if (mf == NULL) {printf ("ошибка\n");}
   //else printf ("Vendor OUI file OK\n");


  //Чтение (построчно) данных из файла в бесконечном цикле
  int lenOUI=0;
   while (1)
   {
     
      if(fscanf(mf,"%x",&masPriorytyVendor[lenOUI].code)==1)
      lenOUI++; 
      else 
      break;
   }
  
   if ( fclose (mf) == EOF) printf ("Error close file\n");
   else printf ("ReadPeioruty OK: %d\n",lenOUI);
}


//////////////////////////////////////////
void readSettings()
{
FILE *mf;
char str[50];


// Открытие файла с режимом доступа «только чтение» и привязка к нему 
   // потока данных

   mf = fopen ("sett","r");

    // Проверка открытия файла
   if (mf == NULL) {printf ("ошибка\n");}
   //else printf ("Vendor OUI file OK\n");
  
      if(fscanf(mf,"%s %s %s",settings.ip,settings.chanel,settings.mode)==3);
	  settings.ip[15]='\0';
    
}
/////////////////////////////////////////

///////////check connect apple ssid
const char  *checkApple()
{
	for(int i=0;i<256;i++)
	{
		if(macBase[countMAC].randomMAC[0]==masSSID[i].addr1[0]&&
		macBase[countMAC].randomMAC[1]==masSSID[i].addr1[1]&&
		macBase[countMAC].randomMAC[2]==masSSID[i].addr1[2]&&
		macBase[countMAC].randomMAC[3]==masSSID[i].addr1[3]&&
		macBase[countMAC].randomMAC[4]==masSSID[i].addr1[4]&&
		macBase[countMAC].randomMAC[5]==masSSID[i].addr1[5])
		{
			return masSSID[i].ssid;
			break;
		}
		if(i==255) return "null";

	}


}



////////////////


const char  *checkMac(u_int8_t mac)
{
	if(mac&0x2)
	{
		return "Local ";
	}
	else
	{
		return "Global";
	}


}

long long current_timestamp() {
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
  //  printf("milliseconds: %lld", milliseconds);
    return milliseconds;
}

void change_chanell()
{
if((current_timestamp()-old_time)>1)
 {	
 	char str[40];
 	sprintf (str,"iwconfig mon0 channel %d",chanell);
	system(str);
 	chanell++;
	if(chanell>14)
	 chanell=1; 
old_time=current_timestamp();
 }
}

void cleanup() {
  pcap_close(handle);
  free(errbuf);
}

void stop(int signo) {
  exit(EXIT_SUCCESS);
}

void another_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, 
	const u_char* packet) 
{ 
	int i=0; 
	static int count=0; 

	printf("Packet Count: %d\n", ++count);             /* Количество пакетов */
	printf("Recieved Packet Size: %d\n", pkthdr->len); /* Длина заголовка */
	printf("Payload:\n");                              /* А теперь данные */
	for(i=0;i<pkthdr->len;i++) { 
		if(isprint(packet[i]))            /* Проверка, является ли символ печатаемым */
			printf("%c ",packet[i]);       /* Печать символа */
		else 
			printf("%x",packet[i]);       /* Если символ непечатаемый, вывод . */
		if((i%16==0 && i!=0) || i==pkthdr->len-1) 
			printf("\n"); 
	}
}


void trap(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
	struct radiotap_header* rt = (struct radiotap_header*) packetptr;
	struct ieee802_11_header* wl = (struct ieee802_11_header*) (packetptr + rt->len);
	
	u_int16_t ctrl_reversed = (wl->f_ctrl>>8) | (wl->f_ctrl<<8);
	u_int8_t version = wl->f_ctrl & 0x3;
	u_int8_t type = (wl->f_ctrl & 0xc) >> 2;
	u_int8_t subtype = (wl->f_ctrl & 0xf0) >> 4;
	u_int8_t flags = (wl->f_ctrl & 0xff00) >> 8;
		u_int8_t tods = flags & 0x1;
		u_int8_t fromds = (flags & 0x2) >> 1;
		u_int8_t morefr = (flags & 0x4) >> 2;
		u_int8_t retry = (flags & 0x8) >> 3;
		u_int8_t powman = (flags & 0x10) >> 4;
		u_int8_t moredata = (flags & 0x20) >> 5;
		u_int8_t wep = (flags & 0x40) >> 6;
		u_int8_t order = (flags & 0x80) >> 7;
if(getOuiPriority((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16))||
   getOuiPriority((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16))||
   getOuiPriority((wl->addr3[2])|(wl->addr3[1] << 8)|(wl->addr3[0] << 16))
   )
{	
	printf("%s;",settings.mac);
	printf("%lld;",current_timestamp());
	printf("%d;", rt->chanell);	
	printf("%d;", rt->signal);	
	printf("0x%04x;", ctrl_reversed);
	
	if (type == 0)//Management
		printf("0;");//
	else if (type == 1)//Control
		printf("1;");
	else if (type == 2)//Data
		printf("2;");

	if (type == 0 && subtype == 0)//Association Request
		printf("00;");
	else if (type == 0 && subtype == 1)//Association Response
		printf("01;");
	else if (type == 0 && subtype == 2)//Reassociation Request
		printf("02;");
	else if (type == 0 && subtype == 3)//Reassociation Response
		printf("03;");
	else if (type == 0 && subtype == 4)//Probe Request
		printf("04;");
	else if (type == 0 && subtype == 5)//Probe Response
		printf("05;");
	else if (type == 0 && subtype == 6)//Timing Advertisement
		printf("06;");
	else if (type == 0 && subtype == 8)//Beacon
		printf("08;");
	else if (type == 0 && subtype == 9)//Beacon
		printf("09;");
	else if (type == 0 && subtype == 10)//Disassociation
		printf("10;");
	else if (type == 0 && subtype == 11)//Authentication
		printf("11;");
	else if (type == 0 && subtype == 12)//Deauthentication
		printf("12;");
	else if (type == 0 && subtype == 13)//Action
		printf("13;");
	else if (type == 0 && subtype == 14)//Action No Ack (NACK)
		printf("14;");


	if (type == 1 && subtype == 2)//Trigger
		printf("02;");
	else if (type == 1 && subtype == 3)//TACK
		printf("03;");
	else if (type == 1 && subtype == 4)//Beamforming Report Poll
		printf("04;");
	else if (type == 1 && subtype == 5)//VHT/HE NDP Announcement
		printf("05;");
	else if (type == 1 && subtype == 6)//Control Frame Extension
		printf("06;");
	else if (type == 1 && subtype == 7)//Control Wrapper
		printf("07;");
	else if (type == 1 && subtype == 8)//Block Ack Request (BAR)
		printf("08;");
	else if (type == 1 && subtype == 9)//Block Ack (BA)
		printf("09;");
	else if (type == 1 && subtype == 10)//PS-Poll
		printf("10;");
	else if (type == 1 && subtype == 11)//RTS
		printf("11;");
	else if (type == 1 && subtype == 12)//CTS
		printf("12;");
	else if (type == 1 && subtype == 13)//ACK
		printf("13;");
	else if (type == 1 && subtype == 14)//CF-End
		printf("14;");
	else if (type == 1 && subtype == 15)//CF-End + CF-ACK
		printf("15;)");

	

	if (type == 2 && subtype == 0)//Data
		printf("00;");
	else if (type == 2 && subtype == 1)//Data + CF-ACK
		printf("01;");
	else if (type == 2 && subtype == 2)//Data + CF-Poll
		printf("02;");
	else if (type == 2 && subtype == 3)//Data + CF-ACK + CF-Poll
		printf("03;");
	else if (type == 2 && subtype == 4)//Null (no data)
		printf("04;");
	else if (type == 2 && subtype == 5)//CF-ACK (no data)
		printf("05;");
	else if (type == 2 && subtype == 6)//CF-Poll (no data)
		printf("06;");
	else if (type == 2 && subtype == 7)//CF-ACK + CF-Poll (no data)
		printf("07;");
	else if (type == 2 && subtype == 8)//QoS Data
		printf("08;");
	else if (type == 2 && subtype == 9)//QoS Data + CF-ACK
		printf("09;");
	else if (type == 2 && subtype == 10)//QoS Data + CF-Poll
		printf("10;");
	else if (type == 2 && subtype == 11)//QoS Data + CF-ACK + CF-Poll
		printf("11;");
	else if (type == 2 && subtype == 12)//QoS Null (no data)
		printf("12;");
	else if (type == 2 && subtype == 13)
		printf("14;");//QoS CF-Poll (no data)
	else if (type == 2 && subtype == 15)
		printf("15;");//QoS CF-ACK + CF-Poll (no data)

	//printf("Flags:0x%x\n", flags);
	printf("%x", tods);//toDS
	printf("%x;", fromds);//fromDS
	//printf("More fragments:%x\n", morefr);
	//printf("Retry:%x\n", retry);
	//printf("Power manag.:%x\n", powman);
	//printf("More data:%x\n", moredata);
	//printf("WEP:%x\n", wep);
	//printf("Order:%x\n", order);

	//printf("Duration:%d\n", wl->dur);
	//printf("Sequence:%d\n", wl->seq);
	

	if(tods == 0 && fromds == 0) {
	
			//Probe Response)
		if(getOuiPriority((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)))
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("%s ;",checkMac(wl->addr1[0]));
		printf("%s ;",getOui((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr1[0];
		masSSID[countSSID].addr1[1]= wl->addr1[1];
		masSSID[countSSID].addr1[2]= wl->addr1[2];
		masSSID[countSSID].addr1[3]= wl->addr1[3];
		masSSID[countSSID].addr1[4]= wl->addr1[4];
		masSSID[countSSID].addr1[5]= wl->addr1[5];
		}
		else if(getOuiPriority((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)))
		{
        printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("%s ;",checkMac(wl->addr2[0]));
		printf("%s ;",getOui((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr2[0];
		masSSID[countSSID].addr1[1]= wl->addr2[1];
		masSSID[countSSID].addr1[2]= wl->addr2[2];
		masSSID[countSSID].addr1[3]= wl->addr2[3];
		masSSID[countSSID].addr1[4]= wl->addr2[4];
		masSSID[countSSID].addr1[5]= wl->addr2[5];
		
		}
		else if(getOuiPriority((wl->addr3[2])|(wl->addr3[1] << 8)|(wl->addr3[0] << 16)))
		{
printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
		wl->addr3[0], wl->addr3[1], wl->addr3[2],
		wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("%s ;",checkMac(wl->addr3[0]));
		printf("%s ;",getOui((wl->addr3[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr3[0];
		masSSID[countSSID].addr1[1]= wl->addr3[1];
		masSSID[countSSID].addr1[2]= wl->addr3[2];
		masSSID[countSSID].addr1[3]= wl->addr3[3];
		masSSID[countSSID].addr1[4]= wl->addr3[4];
		masSSID[countSSID].addr1[5]= wl->addr3[5];
		}
		/*else 	
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
		wl->addr1[0], wl->addr1[1], wl->addr1[2],
		wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("%s ;",checkMac(wl->addr1[0]));
		printf("%s ;",getOui((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr1[0];
		masSSID[countSSID].addr1[1]= wl->addr1[1];
		masSSID[countSSID].addr1[2]= wl->addr1[2];
		masSSID[countSSID].addr1[3]= wl->addr1[3];
		masSSID[countSSID].addr1[4]= wl->addr1[4];
		masSSID[countSSID].addr1[5]= wl->addr1[5];
		}*/
	
	} else if (tods == 0 && fromds == 1) {
		
		if(getOuiPriority((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)))
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("%s ;",checkMac(wl->addr1[0]));
		printf("%s ;",getOui((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr1[0];
		masSSID[countSSID].addr1[1]= wl->addr1[1];
		masSSID[countSSID].addr1[2]= wl->addr1[2];
		masSSID[countSSID].addr1[3]= wl->addr1[3];
		masSSID[countSSID].addr1[4]= wl->addr1[4];
		masSSID[countSSID].addr1[5]= wl->addr1[5];
		}
		else if(getOuiPriority((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)))
		{
        printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("%s ;",checkMac(wl->addr2[0]));
		printf("%s ;",getOui((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr2[0];
		masSSID[countSSID].addr1[1]= wl->addr2[1];
		masSSID[countSSID].addr1[2]= wl->addr2[2];
		masSSID[countSSID].addr1[3]= wl->addr2[3];
		masSSID[countSSID].addr1[4]= wl->addr2[4];
		masSSID[countSSID].addr1[5]= wl->addr2[5];
		
		}
		else if(getOuiPriority((wl->addr3[2])|(wl->addr3[1] << 8)|(wl->addr3[0] << 16)))
		{
printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
		wl->addr3[0], wl->addr3[1], wl->addr3[2],
		wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("%s ;",checkMac(wl->addr3[0]));
		printf("%s ;",getOui((wl->addr3[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr3[0];
		masSSID[countSSID].addr1[1]= wl->addr3[1];
		masSSID[countSSID].addr1[2]= wl->addr3[2];
		masSSID[countSSID].addr1[3]= wl->addr3[3];
		masSSID[countSSID].addr1[4]= wl->addr3[4];
		masSSID[countSSID].addr1[5]= wl->addr3[5];
		}
		/*else
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", //Source address
					 wl->addr3[0], wl->addr3[1], wl->addr3[2],
					 wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("%s ;",checkMac(wl->addr3[0]));
		printf("%s ;",getOui((wl->addr3[2])|(wl->addr3[1] << 8)|(wl->addr3[0] << 16)));

		//write mac from detect apple
		macBase[countMAC].randomMAC[0]=wl->addr3[0];
		macBase[countMAC].randomMAC[1]=wl->addr3[1];
		macBase[countMAC].randomMAC[2]=wl->addr3[2];
		macBase[countMAC].randomMAC[3]=wl->addr3[3];
		macBase[countMAC].randomMAC[4]=wl->addr3[4];
		macBase[countMAC].randomMAC[5]=wl->addr3[5];
		}*/
	
	
	} else if (tods == 1 && fromds == 0) {
		if(getOuiPriority((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)))
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("%s ;",checkMac(wl->addr1[0]));
		printf("%s ;",getOui((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr1[0];
		masSSID[countSSID].addr1[1]= wl->addr1[1];
		masSSID[countSSID].addr1[2]= wl->addr1[2];
		masSSID[countSSID].addr1[3]= wl->addr1[3];
		masSSID[countSSID].addr1[4]= wl->addr1[4];
		masSSID[countSSID].addr1[5]= wl->addr1[5];
		}
		else if(getOuiPriority((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)))
		{
        printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("%s ;",checkMac(wl->addr2[0]));
		printf("%s ;",getOui((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr2[0];
		masSSID[countSSID].addr1[1]= wl->addr2[1];
		masSSID[countSSID].addr1[2]= wl->addr2[2];
		masSSID[countSSID].addr1[3]= wl->addr2[3];
		masSSID[countSSID].addr1[4]= wl->addr2[4];
		masSSID[countSSID].addr1[5]= wl->addr2[5];
		
		}
		else if(getOuiPriority((wl->addr3[2])|(wl->addr3[1] << 8)|(wl->addr3[0] << 16)))
		{
printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
		wl->addr3[0], wl->addr3[1], wl->addr3[2],
		wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("%s ;",checkMac(wl->addr3[0]));
		printf("%s ;",getOui((wl->addr3[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr3[0];
		masSSID[countSSID].addr1[1]= wl->addr3[1];
		masSSID[countSSID].addr1[2]= wl->addr3[2];
		masSSID[countSSID].addr1[3]= wl->addr3[3];
		masSSID[countSSID].addr1[4]= wl->addr3[4];
		masSSID[countSSID].addr1[5]= wl->addr3[5];
		}
		/*else
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", //Source address
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);

		printf("%s ;",checkMac(wl->addr2[0]));
		printf("%s ;",getOui((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));

	//write mac from detect apple
		macBase[countMAC].randomMAC[0]=wl->addr2[0];
		macBase[countMAC].randomMAC[1]=wl->addr2[1];
		macBase[countMAC].randomMAC[2]=wl->addr2[2];
		macBase[countMAC].randomMAC[3]=wl->addr2[3];
		macBase[countMAC].randomMAC[4]=wl->addr2[4];
		macBase[countMAC].randomMAC[5]=wl->addr2[5];
		}*/
		
	} else if (tods == 1 && fromds == 1) {
		if(getOuiPriority((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)))
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr1[0], wl->addr1[1], wl->addr1[2],
					 wl->addr1[3], wl->addr1[4], wl->addr1[5]);
		printf("%s ;",checkMac(wl->addr1[0]));
		printf("%s ;",getOui((wl->addr1[2])|(wl->addr1[1] << 8)|(wl->addr1[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr1[0];
		masSSID[countSSID].addr1[1]= wl->addr1[1];
		masSSID[countSSID].addr1[2]= wl->addr1[2];
		masSSID[countSSID].addr1[3]= wl->addr1[3];
		masSSID[countSSID].addr1[4]= wl->addr1[4];
		masSSID[countSSID].addr1[5]= wl->addr1[5];
		}
		else if(getOuiPriority((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)))
		{
        printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
					 wl->addr2[0], wl->addr2[1], wl->addr2[2],
					 wl->addr2[3], wl->addr2[4], wl->addr2[5]);
		printf("%s ;",checkMac(wl->addr2[0]));
		printf("%s ;",getOui((wl->addr2[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr2[0];
		masSSID[countSSID].addr1[1]= wl->addr2[1];
		masSSID[countSSID].addr1[2]= wl->addr2[2];
		masSSID[countSSID].addr1[3]= wl->addr2[3];
		masSSID[countSSID].addr1[4]= wl->addr2[4];
		masSSID[countSSID].addr1[5]= wl->addr2[5];
		
		}
		else if(getOuiPriority((wl->addr3[2])|(wl->addr3[1] << 8)|(wl->addr3[0] << 16)))
		{
printf("%02x:%02x:%02x:%02x:%02x:%02x;", 
		wl->addr3[0], wl->addr3[1], wl->addr3[2],
		wl->addr3[3], wl->addr3[4], wl->addr3[5]);
		printf("%s ;",checkMac(wl->addr3[0]));
		printf("%s ;",getOui((wl->addr3[2])|(wl->addr2[1] << 8)|(wl->addr2[0] << 16)));
		masSSID[countSSID].addr1[0]= wl->addr3[0];
		masSSID[countSSID].addr1[1]= wl->addr3[1];
		masSSID[countSSID].addr1[2]= wl->addr3[2];
		masSSID[countSSID].addr1[3]= wl->addr3[3];
		masSSID[countSSID].addr1[4]= wl->addr3[4];
		masSSID[countSSID].addr1[5]= wl->addr3[5];
		}
		/*else
		{
		printf("%02x:%02x:%02x:%02x:%02x:%02x;",  //Source address
					 wl->addr4[0], wl->addr4[1], wl->addr4[2],
					 wl->addr4[3], wl->addr4[4], wl->addr4[5]);

		printf("%s ;",checkMac(wl->addr4[0]));
		printf("%s ;",getOui((wl->addr4[2])|(wl->addr4[1] << 8)|(wl->addr4[0] << 16)));
		
		}*/
	}
	//////////////////////SSID DETECT/////////////////////////////////////////////////////
	
if (type == 0 && subtype == 5) //Probe Response
{
	int tst=0;
    int count=0;
	int flag =0;
for(int i=48;i<packethdr->len;i++) { 
if(isprint(packetptr[i])){

							if(packetptr[i-2]==0x00)
							{
								int sds=packetptr[i-1];
								
								if(sds>4&&sds<20)
								{
								while (count<sds)
									{
									
										printf("%c",packetptr[i]);
										masSSID[countSSID].ssid[count]=packetptr[i];
										i++;
										count++;
										tst=1;
																			
									}
									
									for(;count<20;count++)
									{
										masSSID[countSSID].ssid[count]=0;
									}
								
									flag=1;
									flagSSD=1;
									printf(";");
									break;
								}
								
								
							}

                         }

}
	
	countSSID++;
	if(tst==0) flagSSD=0;
} 
else
{
//printf("null;");
flagSSD=0;
}
   

 //!!!!!!!!!!!!!!!!!!!!!!END!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


	//////////////////////MD5 get PROBE REQ///////////////////////////////////////////////////
/*
if (type == 0 && subtype == 44) //Probe Response
{
	
	char buff[1200];
    char perem[3];
	//memset(buff,0,sizeof(buff));
	//char tst[] =" ";
	
	

	int count=0;
	char a0=0;
	char a1=0;

	char a00=0;
	char a11=0;

	int cn=0;
	for(int i=0;i<packethdr->len;i++)
	{ 
     
       // printf("%02x",packetptr[i]);
	    a0=cp1251(packetptr[i] >> 4);
	    a1=cp1251(packetptr[i] & 0xf);
		buff[cn++]=a0;
	    buff[cn++]=a1;
	   
	  
	
	}

	MDString(buff);
	
} 
else
{
printf(";");
}
 */  

 //!!!!!!!!!!!!!!!!!!!!!!END!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!























//!!!!!!!!!!!!!!!!!!!!!!DHCP DETECT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
if (type == 2){ //dhcp detect
int flag =0;
int flagNull=0;
 		for(int i=0;i<packethdr->len;i++) { 
		if(packetptr[i]==0x63&&packetptr[i+1]==0x82&&packetptr[i+2]==0x53&&packetptr[i+3]==0x63){
			u_int8_t count=0;
			if(flagNull==0&&flagSSD==0){
				printf("null;");flagSSD=5;
				flagNull=1;
				}///if not find ssid
			while (i<packethdr->len)
			{
			 if(isprint(packetptr[i])){
				 //option 12 Host name
				if(packetptr[i-2]==0x0c)
				 {
					 int sds=packetptr[i-1];
					 while (count<sds)
				    	{
				     	printf("%c",packetptr[i]);
						i++;
					  	count++;
				 		}
						count=0;// null for next optin
						printf(";");
						flag =1;
				 }
				 //////////////

				 //option 60
				if(packetptr[i-2]==0x3c)
				 {
					 int sds=packetptr[i-1];
					 while (count<sds)
				    	{
				     	printf("%c",packetptr[i]);
						i++;
					  	count++;
				 		}
						count=0;
						printf(";");
						flag=2;
				 }
				 //////////////
				 
			     
			 }
			 i++;     
			}	
		 break;
		}
		else if(packetptr[i]==0x61&&packetptr[i+1]==0x70&&packetptr[i+2]==0x70&&packetptr[i+3]==0x6c&&packetptr[i+4]==0x65)//check apple
		{
			flag=4;
			printf("%s;",checkApple());
			printf("apple;"); 
			printf("null;");
			break;
		}
		
	}
			if(flag==0)
			{
				//chek func name ssid
				
		if(flagSSD==0){printf("null;");}
			printf("null;");
			printf("null;");

			}
	}
	else
	{
	if(flagSSD==0){printf("null;");}
	else
	{
		if (type == 0 && subtype == 5)
		{
			int df=55;
		} 
	}

	printf("null;");
	printf("null;");
	}
	

//!!!!!!!!!!!!!!!!!!!!!!END!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 
 




	printf( "\n");
	//change_chanell();//next chanell afte 1ms
 }
}

int main(int argc, char** argv) {
 GetMacRaps();
  readOUI();
  readOUI_Priority();
 // readSettings();
 // printf("Time      ChannelSignalframe typeTypesubtypetoDS/fromDSmacDHCP(12) \n");
 

  atexit(cleanup);
  signal(SIGINT, stop);
  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create("mon0", errbuf);
  pcap_set_rfmon(handle, 1); // monitor mode
  pcap_set_snaplen(handle, 65535);
  pcap_activate(handle);
  pcap_loop(handle, -1, trap, NULL);
;
}
























//////////////////////////md5

/* typedef a 32 bit type */
typedef unsigned long int UINT4;

/* Data structure for MD5 (Message Digest) computation */
typedef struct {
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
  UINT4 buf[4];                                    /* scratch buffer */
  unsigned char in[64];                              /* input buffer */
  unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;

void MD5Init ();
void MD5Update ();
void MD5Final ();


static void Transform ();

static unsigned char PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (mdContext)
MD5_CTX *mdContext;
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (mdContext, inBuf, inLen)
MD5_CTX *mdContext;
unsigned char *inBuf;
unsigned int inLen;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (mdContext)
MD5_CTX *mdContext;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  MD5Update (mdContext, PADDING, padLen);

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (buf, in)
UINT4 *buf;
UINT4 *in;
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
  FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
  FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */
  FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */
  FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */
  FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */
  FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */
  FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
  GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
  GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */
  GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
  GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */
  GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
  GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
  GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
  HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */
  HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
  HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */
  HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
  HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
  HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */
  HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
  II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
  II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
  II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
  II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
  II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
  II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */
  II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}



/* -- include the following file if the file md5.h is separate -- */
/* #include "md5.h" */

/* Prints message digest buffer in mdContext as 32 hexadecimal digits.
   Order is from low-order byte to high-order byte of digest.
   Each byte is printed with high-order hexadecimal digit first.
 */
static void MDPrint (mdContext)
MD5_CTX *mdContext;
{
  int i;

  for (i = 0; i < 16; i++)
    printf ("%02x", mdContext->digest[i]);
}

/* size of test block */
#define TEST_BLOCK_SIZE 1000

/* number of blocks to process */
#define TEST_BLOCKS 10000

/* number of test bytes = TEST_BLOCK_SIZE * TEST_BLOCKS */
static long TEST_BYTES = (long)TEST_BLOCK_SIZE * (long)TEST_BLOCKS;

/* A time trial routine, to measure the speed of MD5.
   Measures wall time required to digest TEST_BLOCKS * TEST_BLOCK_SIZE
   characters.
 */
static void MDTimeTrial ()
{
  MD5_CTX mdContext;
  time_t endTime, startTime;
  unsigned char data[TEST_BLOCK_SIZE];
  unsigned int i;

  /* initialize test data */
  for (i = 0; i < TEST_BLOCK_SIZE; i++)
    data[i] = (unsigned char)(i & 0xFF);

  /* start timer */
  printf ("MD5 time trial. Processing %ld characters...\n", TEST_BYTES);
  time (&startTime);

  /* digest data in TEST_BLOCK_SIZE byte blocks */
  MD5Init (&mdContext);
  for (i = TEST_BLOCKS; i > 0; i--)
    MD5Update (&mdContext, data, TEST_BLOCK_SIZE);
  MD5Final (&mdContext);

  /* stop timer, get time difference */
  time (&endTime);
  MDPrint (&mdContext);
  printf (" is digest of test input.\n");
  printf
    ("Seconds to process test input: %ld\n", (long)(endTime-startTime));
  printf
    ("Characters processed per second: %ld\n",
     TEST_BYTES/(endTime-startTime));
}

/* Computes the message digest for string inString.
   Prints out message digest, a space, the string (in quotes) and a
   carriage return.
 */
static void MDString (inString)
char *inString;
{
 
  MD5_CTX mdContext;
  unsigned int len = strlen (inString);

  MD5Init (&mdContext);
  MD5Update (&mdContext, inString, len);
  MD5Final (&mdContext);
  MDPrint (&mdContext);
 // printf (" \"%s\"", inString);
}

