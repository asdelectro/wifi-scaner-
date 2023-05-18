#include <stdio.h>
#include <string.h>
struct OUI
{
    __uint32_t code;
    char name[20];
};

struct OUI masVendor[28870];

__uint32_t hexNumb=0;
char nameVendor[20];
char* getOui(int ouCode)
{
int i=0;
while (masVendor[i].code!=NULL)
{
   if(masVendor[i].code==ouCode)
   {
       return masVendor[i].name;
       break;
   }
   i++;
   if (masVendor[i].code==NULL)
   {
  
   return "unknown";

   } 
}

}

int main(int argc, char** argv) {

FILE *mf;
char str[50];


// Открытие файла с режимом доступа «только чтение» и привязка к нему 
   // потока данных

   mf = fopen ("oui_vendor","r");

    // Проверка открытия файла
   if (mf == NULL) {printf ("ошибка\n"); return -1;}
   else printf ("Vendor OUI file OK\n");


  //Чтение (построчно) данных из файла в бесконечном цикле
  int lenOUI=0;
   while (1)
   {
     
      if(fscanf(mf,"%x %s",&masVendor[lenOUI].code,&masVendor[lenOUI].name )==2)
      lenOUI++; 
      else 
      break;
   }
  
   if ( fclose (mf) == EOF) printf ("Error close file\n");
   else printf ("ReadFileOUI OK: %d\n",lenOUI);

   printf ("%s \n",getOui(0x107BEF));

   return 0;
}