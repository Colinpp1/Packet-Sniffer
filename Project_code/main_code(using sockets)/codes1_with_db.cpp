        #include<fstream> //streaming files access to files etc       
        #include<iomanip> 
        #include"timestamp.hpp" //timestamp for password timeout in code
        #include<boost/lexical_cast.hpp>// easy conversion from int to string 
        #include<iostream> //for input output functions
        #include<netinet/in.h>
	#include<errno.h>
	#include<netdb.h>
	#include<stdio.h> //For standard things
	#include<stdlib.h>    //malloc
	#include<string.h>    //strlen 
	#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
	#include<netinet/udp.h>   //Provides declarations for udp header
	#include<netinet/tcp.h>   //Provides declarations for tcp header
	#include<netinet/ip.h>    //Provides declarations for ip header
	#include<netinet/if_ether.h>  //For ETH_P_ALL
	#include<net/ethernet.h>  //For ether_header
	#include<sys/socket.h>
	#include<arpa/inet.h>
	#include<sys/ioctl.h>
	#include<sys/time.h>
	#include<sys/types.h>
	#include<unistd.h>
        #include<sqlite3.h>  // For database opertations
        #include "sqlite3.h" // For database operations using sqlite v 3
        #include <string> // For String operations
        #include <vector> // For Vector operations
        #include <cmath> //For Mathematical operations
       
int done =0;

using namespace std;
vector<int> sequence_no(1000000); //Method for

int intlen(float start) {                 //Method for getting the length of an integer used it in the output.txt file creation
    int end = 0;
    while(start >= 1) {
        start = start/10;
        end++;
    }
    return end; }

bool login() //method for authentification
{
string    firstName,
        lastName,
        userName,
        password;
ifstream in;
    cout <<"\n";
    cout << setw(30)<< "\n\tPlease login, login must consist of only TWO names seperated by a space:\n" ;
    cout << "\n\tEnter name:\t";
    cin >> firstName >> lastName;
    userName = firstName+" "+lastName;
    in.open("password.txt");
    string inbuf;  
    while( !in.eof())
        {
        getline(in,inbuf);       
        if(inbuf == userName)
            {
            cout << "\n\tUser: " << userName << " found.\n\n\tPlease enter your password: " ;
            cin >>password;
            getline(in,inbuf);                          
            if(inbuf == password)
                {
                cout << "\n\tPassword verified."<< endl ;
                                in.close();
                return true;
                }
            else
                {
                cout << "\n\tPassword incorrect. " << endl;
                in.close();
                return false;            
                }
            }           
        }
    cout<<"user name not found"<<endl;
in.close();
return false;
}
 
	void ProcessPacket(unsigned char* , int);
        void print_tcp_packet(unsigned char *  , int );
	void print_ip_header(unsigned char* , int);
	void print_udp_packet(unsigned char * , int );
	void print_icmp_packet(unsigned char* , int );
	void PrintData (unsigned char* , int);
	 
        
        ofstream outfile("outpt.txt");
      
	FILE *logfile; 
	struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j,w,ib=0,seq,source_p,dest_p,source_a,dest_port,protocol,count=0,k=0,a=0,rtm=0,source_ip,dest_ip,seq1,ack1,urge,rt;
int rc,ack;	 
string now,s_ip,d_ip;

      
        string q="";
        string dbName="work.dat";
        sqlite3*db;
        char *zErrMsg=0;
	int main(){
            cout <<"\n*Welcome to packet capture v 2.4 where provide u with packets for free*"<<endl;
            cout <<"Enter ctr z to exit our application at any time"<<endl;
          
          login();//login
        if(login()==false)
         {cout<<"sorry can't enter"<<endl;
           return 0;
             }
            else {cout<<"well done"<<endl;}

            cout<<"\n          WELL DONE ON lOGGING IN IT'S TIME TO CAPTURE SOME PACKETS !:      \n"<<endl;
            cout << "How many packets do you wish to capture: " <<endl;
            cin >> w;
            cout << "you may also want to look at our app capturing packets on the network interface card !"<<endl;
            cout<<"For your packets go to ...0707021p/now/bill/project "<<endl;
            cout <<"All rights reserved Colin & Charles 2012"<<endl ;
            sqlite3* db;
            char *zErrMsg=0;
            int rc;
            string q="";
            string dbName="charlax.dat";
            //Attempt to open database,if not then we create it.
             
           int sqlite3_enable_shared_cache(1);            
		rc=sqlite3_open(dbName.c_str(),&db);

            if(rc){
            fprintf(stderr,"Can't open database: %s\n",sqlite3_errmsg(db));
          
            exit(1);}
   	 
            //Setting up query for one table
            q ="CREATE TABLE t_TCP12"       //sqlite3 database creation for tcp pkts
             "("
              "'ID'INTEGER PRIMARY KEY AUTOINCREMENT,"
	       "'Source_IP'INTEGER KEY,"
	       "'Destination_IP'INTEGER KEY,"
               "'Source_Port'TEXT,"
               "'Destination_Port'INTEGER KEY,"
               "'Sequence_Number'INTEGER KEY,"
	       "'Acknowledgement_Number'INTEGER KEY,"
	      "'Urgent_Flag'INTEGER KEY,"
	       "'Acknowledgement_Flag'INTEGER KEY,"
	       "'Push_Flag'INTEGER KEY,"
	       "'Reset_Flag'INTEGER KEY,"
	       "'Synochronize_Flag'INTEGER KEY,"
	       "'Finish_Flag'INTEGER KEY,"
	       "'Window'INTEGER KEY,"
	       "'Checksum'INTEGER KEY,"
	       "'Urgent_Pointer'INTEGER KEY"
               //"'Http_MSG'INTEGER KEY"
	      ");";



		
              rc =sqlite3_exec(db,q.c_str(),NULL,0,&zErrMsg);
		sqlite3_close(db);
              if(rc!=SQLITE_OK){
              fprintf(stderr,"SQL error:%s\n",zErrMsg);
              sqlite3_free(zErrMsg);
               sqlite3_close(db);
}
                
	    int saddr_size , data_size;
	    struct sockaddr saddr;
	 
	    unsigned char *buffer = (unsigned char *) malloc(65536); 
	    
           
           ;
           // ofstream outfile("output.txt");
	    logfile=fopen("works.txt","w");
	    if(logfile==NULL)
	    {
	        printf(" Can not create log.txt file.");}
             if(outfile==NULL)
             {printf("Sorry Can not create out.txt file. ");}
	    
	    printf("Starting...\n");
	    
	    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	    setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	 
	    if(sock_raw < 0)
	    {
	        //Print the error with proper message
	        perror("Socket Error");
	        return 1;
	    } 
            outfile<<"|TCP   |Source Port |Destination Port |Sequence Number  |Acknowledge Number |Source IP        |Dest IP          |Urgent Flag | Retrans|\n"; 
            
	    while(total<=w)
	    {
	        saddr_size = sizeof saddr;
	        //Receive a packet
                cout<<""<<endl;
	        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
	        if(data_size < 0 )
	        {
	            printf("Recvfrom error , failed to get packets\n");
	            return 1;
	        }
	        //Now process the packet
	        ProcessPacket(buffer , data_size);
	    }
	    close(sock_raw);
	    printf("Finished");
	    return 0;
	}

	void ProcessPacket(unsigned char* buffer, int size)
	{
	    //Get the IP Header part of this packet , excluding the ethernet header
	    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	    ++total;
	    switch (iph->protocol) //Check the Protocol and do accordingly...
	    {
	        case 1:  //ICMP Protocol
	            ++icmp;
	            print_icmp_packet( buffer , size);
	            break;
	 
	        case 2:  //IGMP Protocol
	            ++igmp;
	            break;
	 
	       case 6:  //TCP Protocol
                   
	            ++tcp;
	            print_tcp_packet(buffer , size);
	            break;
	 
	        case 17: //UDP Protocol
	            ++udp;
	            print_udp_packet(buffer , size);
	            break;
	 
	        default: //Some Other Protocol like ARP etc.
	            ++others;
	            break;
	    }
	    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d  RTM: %d Total : %d\r", tcp , udp , icmp , igmp , others ,rtm, total);
        
	}
	 
	void print_ethernet_header(unsigned char* Buffer, int Size)
	{
	    struct ethhdr *eth = (struct ethhdr *)Buffer;
	 
    fprintf(logfile , "\n");
	    fprintf(logfile , "Ethernet Header\n");
	    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	    fprintf(logfile , "   |-Protocol            : %u \n",protocol=(unsigned short)eth->h_proto);
	}

	void print_ip_header(unsigned char* Buffer, int Size)
	{
	    print_ethernet_header(Buffer , Size);
	 
	    unsigned short iphdrlen;
	 
	    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	    iphdrlen =iph->ihl*4;
	 
	    memset(&source, 0, sizeof(source));
	    source.sin_addr.s_addr = iph->saddr;
	 
	    memset(&dest, 0, sizeof(dest));
	    dest.sin_addr.s_addr = iph->daddr;
	 
	    fprintf(logfile , "\n");
	    fprintf(logfile , "   IP Header\n");
	    fprintf(logfile , "   IP Version        : %d\n",(unsigned int)iph->version);
	    fprintf(logfile , "   IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	    fprintf(logfile , "   Type Of Service   : %d\n",(unsigned int)iph->tos);
	    fprintf(logfile , "   IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	    fprintf(logfile , "   Identification    : %d\n",ntohs(iph->id));
	    fprintf(logfile , "   TTL      : %d\n",(unsigned int)iph->ttl);
	    fprintf(logfile , "   Protocol : %d\n",(unsigned int)iph->protocol);
	    fprintf(logfile , "   Checksum : %d\n",ntohs(iph->check));
	    fprintf(logfile , "   Source IP        : %s\n",inet_ntoa(source.sin_addr));
	    fprintf(logfile , "   Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
            s_ip=inet_ntoa(source.sin_addr);//for output.txt file
            d_ip=inet_ntoa(dest.sin_addr);
            
	}
	 
	void print_tcp_packet(unsigned char* Buffer, int Size)
	{
            a=a+rt; //count no of retransmitted packets
           
        
            
	    unsigned short iphdrlen;
	 
	    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	    iphdrlen = iph->ihl*4;
	 
	    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	 
	    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	 
	    fprintf(logfile , "\n\n ...................TCP Packet................... \n"); 
	 
	    print_ip_header(Buffer,Size);
	 
	    fprintf(logfile , "\n");
	    fprintf(logfile , "   TCP Header\n");
	    fprintf(logfile , "   Source Port : %u\n",source_p=ntohs(tcph->source));
	    fprintf(logfile , "   Destination Port : %u\n",dest_p=ntohs(tcph->dest));string dest =boost::lexical_cast<string>(dest_p);
	    fprintf(logfile , "   Sequence Number : %u\n",seq=ntohl(tcph->seq));  string s =boost::lexical_cast<string>(seq);seq1=abs(seq);
	    fprintf(logfile , "   Acknowledge Number: %u\n",ack=ntohl(tcph->ack_seq)); ack1=abs(ack);
	    fprintf(logfile , "   Header Length : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	    fprintf(logfile , "   Urgent Flag          : %d\n",(unsigned int)tcph->urg);urge=abs(tcph->urg);
            fprintf(logfile , "   Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	    fprintf(logfile , "   Push Flag            : %d\n",(unsigned int)tcph->psh);
	    fprintf(logfile , "   Reset Flag           : %d\n",(unsigned int)tcph->rst);
	    fprintf(logfile , "   Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	    fprintf(logfile , "   Finish Flag          : %d\n",(unsigned int)tcph->fin);
	    fprintf(logfile , "   Window         : %d\n",ntohs(tcph->window));
	    fprintf(logfile , "   Checksum       : %d\n",ntohs(tcph->check));
	    fprintf(logfile , "   Urgent Pointer : %d\n",tcph->urg_ptr);
	    fprintf(logfile , "\n");
fprintf(logfile , "                   DATADump           ");
//now for our output.txt file entries
outfile<<"|"<<tcp<<setw(7-intlen(tcp))<<"|"<<source_p<<setw(13-intlen(source_p))<<"|"<<dest_p<<setw(18-intlen(dest_p))<<"|"<<(seq1)<<setw(18-intlen(seq1))<<"|"<<ack1<<setw(20-intlen(ack1))<<"|"<<s_ip<<setw(4)<<"|"<<setw(1)<<d_ip<<setw(4)<<"|"<<setw(1)<<urge<<setw(12)<<"|"<<setw(1)<<a<<"       |\n";        

 
	    fprintf(logfile , "IP Header\n");
	    PrintData(Buffer,iphdrlen);
	 
	    fprintf(logfile , "TCP Header\n");
	    PrintData(Buffer+iphdrlen,tcph->doff*4);
	 
	    fprintf(logfile , "Data Payload\n");
	    PrintData(Buffer + header_size , Size - header_size );
	 
	    fprintf(logfile , "\n......................................................");
             sequence_no[tcp]=seq;

          /*for database if you want to use it  q="INSERT INTO t_TCP12('Source_IP','Destination_IP','Source_Port','Sequence_Number','Acknowledgement_Flag','Push_Flag','Reset_Flag','Synochronize_Flag','Finish_Flag','Window','Checksum','Urgent_Pointer')VALUES(0,0,'"+s+"','"+s+"',0,0,0,0,0,0,0,0);";
//cout<<"this is "+s<<endl;
rc=sqlite3_open(dbName.c_str(),&db);
rc =sqlite3_exec(db,q.c_str(),NULL,0,&zErrMsg);
sqlite3_close(db);
//cout<<q<<endl;
if(rc!=SQLITE_OK){
//fprintf(stderr,"SQL error: %s\n",zErrMsg);
sqlite3_free(zErrMsg);*/
    
//Method for retransmission

 if (tcp>=1){
      if(sequence_no[tcp] ==sequence_no[tcp-1])
         rt=1;
         else rt=0;
          }
     else{ rt=0;}       
}
       
           
	
	 
	void print_udp_packet(unsigned char *Buffer , int Size)
	{
	 
	    unsigned short iphdrlen;
	 
	    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	    iphdrlen = iph->ihl*4;
	 
	    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	 
	    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	 
	    fprintf(logfile , "\n\n..........................UDP Packet...................\n");
	 
	    print_ip_header(Buffer,Size);          
	 
	    fprintf(logfile , "\nUDP Header\n");
	    fprintf(logfile , "   Source Port      : %d\n" , ntohs(udph->source));
	    fprintf(logfile , "   Destination Port : %d\n" , ntohs(udph->dest));
	    fprintf(logfile , "   UDP Length       : %d\n" , ntohs(udph->len));
	    fprintf(logfile , "   UDP Checksum     : %d\n" , ntohs(udph->check));
	 	    fprintf(logfile , "\n");
	    fprintf(logfile , "IP Header\n");
	    PrintData(Buffer , iphdrlen);
	 
	    fprintf(logfile , "UDP Header\n");
	    PrintData(Buffer+iphdrlen , sizeof udph);
	 
	    fprintf(logfile , "Data Payload\n");   
	 
	    //Move the pointer ahead and reduce the size of string
	    PrintData(Buffer + header_size , Size - header_size);
	 
	    fprintf(logfile , "\n------------------------------------------------------------");
	}
	 
	void print_icmp_packet(unsigned char* Buffer , int Size)
	{
	    unsigned short iphdrlen;
	 
	    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	    iphdrlen = iph->ihl * 4;
	 
	    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	 
	    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	 
	    fprintf(logfile , "\n\n.............................ICMP Packet..........................\n");
	 
	    print_ip_header(Buffer , Size);
	 
	    fprintf(logfile , "\n");
	 
	    fprintf(logfile , "ICMP Header\n");
	    fprintf(logfile , "   Type : %d",(unsigned int)(icmph->type));
	 
	    if((unsigned int)(icmph->type) == 11)
	    {
	        fprintf(logfile , "  (TTL Expired)\n");
	    }
	    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	    {
	        fprintf(logfile , "  (ICMP Echo Reply)\n");
	    }
	 
	    fprintf(logfile , "   Code : %d\n",(unsigned int)(icmph->code));
	    fprintf(logfile , "   Checksum : %d\n",ntohs(icmph->checksum));   
	    fprintf(logfile , "\n");
	    fprintf(logfile , "IP Header\n");
	    PrintData(Buffer,iphdrlen);
	 
	    fprintf(logfile , "UDP Header\n");
	    PrintData(Buffer + iphdrlen , sizeof icmph);
	 
	    fprintf(logfile , "Data Payload\n");   
	 
	    //Move the pointer ahead and reduce the size of string
	    PrintData(Buffer + header_size , (Size - header_size) );
	 
	    fprintf(logfile , "\n---------------------------------------------------------------");
	}
	 
	void PrintData (unsigned char*data , int Size)//method for http message creation 
	{
	    int i , j;
	    for(i=0 ; i < Size ; i++)
	    {
	        if( i!=0 && i%16==0)   
	        {
	            fprintf(logfile , "         ");
	            for(j=i-16 ; j<i ; j++)
	            {
	                if(data[j]>=32 && data[j]<=128)
	                    fprintf(logfile , "%c",(unsigned char)data[j]); 
	 
	                else fprintf(logfile , "."); 
	            }	            fprintf(logfile , "\n");
	        }
	 
	        if(i%16==0) fprintf(logfile , "   ");
	            fprintf(logfile , " %02X",(unsigned int)data[i]);
	 
	        if( i==Size-1)  //print the last spaces
	        {
            for(j=0;j<15-i%16;j++)
	            {
	              fprintf(logfile , "   "); //extra spaces
	            }
	 
	            fprintf(logfile , "         ");
	 
	            for(j=i-i%16 ; j<=i ; j++)
	            {	                if(data[j]>=32 && data[j]<=128)
	                {
	                  fprintf(logfile , "%c",(unsigned char)data[j]);
	                }
	                else
	                {
	                  fprintf(logfile , ".");
	                }
	            }
	 
	            fprintf(logfile ,  "\n" );
	        }
//ifstream in(log.c_str); // Open for reading
//ofstream out(clone.c_str); // Open for writing
//string s;
//while(getline(in, s))
//out << s << "\n";

     }
	}
