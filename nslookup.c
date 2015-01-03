#include<stdio.h>	
#include<string.h>	
#include<stdlib.h>	
#include<sys/socket.h>	
#include<sys/time.h>
#include<arpa/inet.h>	
#include<netinet/in.h>
#include<unistd.h>	

char dns_servers[3][100];	/*primary,seconday and user specified DNS*/

#define T_A 1 			/*Ipv4 address*/
#define T_NS 2 			/*Nameserver*/
#define T_CNAME 5 		/*canonical name*/
#define T_SOA 6 		/*start of authority zone */
#define T_PTR 12 		/*domain name pointer */
#define T_MX 15 		/*Mail server*/

static void reverseIP(char *,char *);
static void ngethost (unsigned char* , int);
static void removeDotsFromName(unsigned char*,unsigned char*);
static unsigned char* ReadName (unsigned char*,unsigned char*,int*);


/*The structure of the DNS packet will be:
	16 bits:ID
	16 bits:header
	16 bits:question
	16 bits:answer
	16 bits:authoritative answer
	16 bits:additional info*/

/*DNS header*/
struct DNS_HEADER
{
	unsigned short id; 	// identification number

	unsigned char rd :1; 	// recursion desired
	unsigned char tc :1; 	// truncated message
	unsigned char aa :1; 	// authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; 	// query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; 	// checking disabled
	unsigned char ad :1; 	// authenticated data
	unsigned char z :1; 	// reserved and unused
	unsigned char ra :1; 	// recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

struct QUESTION				/*QUESTION DATA*/
{
	unsigned short qtype;		/*query type:IN,NS,CNAME,SOA,PTR,MX*/
	unsigned short qclass;		/*query class:IN or CHAOS*/
};


#pragma pack(push, 1)
struct R_DATA				/*RESOURCE RECORD DATA*/
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)


struct RES_RECORD			/*RESOURCE RECORD FIELD:AUTHORITATIVE,ANSWER or ADDITIONAL*/
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

typedef struct				/*QUESTION FIELD*/
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

int main( int argc , char *argv[])
{
	unsigned char hostname[100];
	char *reverse;
	int qtype=T_A;
	if(argc<2)
	{
		printf("USAGE:lookup <HOSTNAME/HOSTIP> <DNS> <QUERYTYPE>\n");
		printf("QUERY TYPES:\n");
		printf("IPV4 : 1\n");
		printf("NAMESERVER : 2\n");
		printf("CANONICAL NAME : 5\n");
		printf("START OF AUTHORITY : 6\n");
		printf("REVERSE QUERY : 12\n");
		printf("MESSAGE EXCHANGE : 15\n");
		return 0;
	}
	if(argc>2)
	{
		strcpy(dns_servers[0] ,  argv[2]);		/*USER SPECIFIED DNS*/
		strcpy(dns_servers[2] , "127.0.1.1");		/*DEFAULT SECONDARY DNS*/
		strcpy(dns_servers[1] , "172.31.1.130");	/*DEFAULT PRIMARY DNS*/
	}
	else if(argc==2)
	{
		strcpy(dns_servers[1] , "127.0.1.1");
		strcpy(dns_servers[0] , "172.31.1.130");
	}
	if(argc==4)
	{
		if(strcmp(argv[3],"15")==0)
			qtype=15;
		else if(strcmp(argv[3],"12")==0)
			qtype=12;
		else
			qtype=argv[3][0]-'0';
	}

	/*Check whether the second argument is for forward lookup or reverse lookup*/
	int flag=1;
	int i;
	for(i=0;i<strlen(argv[1]);i++)
	{
		if(argv[1][i] !='.' && !(argv[1][i]>='0' && argv[1][i]<='9'))
		{
			flag=0;
			break;
		}
	}
	if(flag==1)				/*reverse query*/
	{
		reverseIP(argv[1],reverse);
		ngethost(reverse,12);
	}
	else					/*forward query*/
		ngethost(argv[1] ,qtype);
	return 0;
}

void reverseIP(char *addr, char *tar )		/*change a.b.c.d to d.c.b.a.in-addr.arpa*/
{
        int i,j,count_dots=0,pos=0;
        char buffer[10];
	for(i=strlen(addr)-1;i>=0;i--)
	{
		if(addr[i]=='.')
		{
			for(j=count_dots-1;j>=0;j--)
			{
				*(tar+pos)=buffer[j];
				pos++;
			}
			*(tar+pos)='.';
			pos++;
			count_dots=0;
		}
		else
		{
			buffer[count_dots]=addr[i];
			count_dots++;
		}
	}
	for(j=count_dots-1;j>=0;j--)
	{
		*(tar+pos)=buffer[j];
		pos++;
	}			
        char *arpa = ".in-addr.arpa";
        for(i=0;i<14;i++)
        {
                *(tar+pos) = *arpa;
		pos++;
                arpa++;
        }
}

/*perform nslookup*/
void ngethost(unsigned char *host , int query_type)
{
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a,dest;
	struct timeval timeout;
	timeout.tv_sec = 10; 

	struct RES_RECORD answers[50],auth[50],addinfo[50]; 

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	printf("Resolving %s" , host);

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); 
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));	/*set timeout on this socket*/

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); 

	dns = (struct DNS_HEADER *)&buf;			/*DNS HEADER*/

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; 
	dns->opcode = 0; 				/*standard query*/
	dns->aa = 0; 			
	dns->tc = 1; 
	dns->rd = 1; 					/*recursion desired*/
	dns->ra = 0; 
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); 
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];					     /*DNS QUESTION NAME.ANY JUNK VALUE WILL DO*/

	removeDotsFromName(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; /*DNS QUESTION TYPE AND CLASS*/

	qinfo->qtype = htons( query_type ); 
	qinfo->qclass = htons(1); 

	printf("\nSending Packet to %s\n",dns_servers[0]);
	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		printf("sendto failed on DNS %s.Attempting to send via %s..\n",dns_servers[0],dns_servers[1]);
		dest.sin_addr.s_addr = inet_addr(dns_servers[1]);
		if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
		{
			printf("sendto failed on alternate DNS as well.\n");
			if(strcmp(dns_servers[2], "127.0.1.1")==0)
			{
				dest.sin_addr.s_addr = inet_addr(dns_servers[2]);
				printf("Final attempt on secondary DNS..\n");
				if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
				{
					printf("Failed yet again..Aborting...\n");
					return;
				}
			}
			else
				return;
		}
	}

	printf("Querying done\n");

	printf("Receiving answer...\n");
	i=sizeof(dest);
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
		return;
	}
	printf("Answer received\n");

	dns = (struct DNS_HEADER*) buf;
	
	if(dns->ra==0)
	{
		printf("Recursion not supported..quitting\n");
		return;
	}
	
	if(dns->aa==0)
		printf("The server used is a non-authoritative server in the domain\n");
	else
		printf("The server used is an authoritative server in the domain\n");


	if(dns->rcode==0)
	{
		reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];	/*THE RESPONSE*/

		printf("\nThe response contains : ");
		printf("\n %d Questions.",ntohs(dns->q_count));
		printf("\n %d Answers.",ntohs(dns->ans_count));
		printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
		printf("\n %d Additional records.\n\n",ntohs(dns->add_count));

		stop=0;

		for(i=0;i<ntohs(dns->ans_count);i++)
		{
			answers[i].name=ReadName(reader,buf,&stop);	
			reader = reader + stop;

			answers[i].resource = (struct R_DATA*)(reader);
			reader = reader + sizeof(struct R_DATA);

			if(ntohs(answers[i].resource->type) == 1) 	/*read address*/
			{
				answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

				for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
					answers[i].rdata[j]=reader[j];

				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

				reader = reader + ntohs(answers[i].resource->data_len);
			}
			else						/*read name*/
			{
				answers[i].rdata = ReadName(reader,buf,&stop);
				reader = reader + stop;
			}
		}

		//read authorities
		for(i=0;i<ntohs(dns->auth_count);i++)			
		{
			auth[i].name=ReadName(reader,buf,&stop);
			reader+=stop;

			auth[i].resource=(struct R_DATA*)(reader);
			reader+=sizeof(struct R_DATA);

			if(ntohs(auth[i].resource->type)==1)		/*read address*/
                        {
                                auth[i].rdata = (unsigned char*)malloc(ntohs(auth[i].resource->data_len));
                                for(j=0;j<ntohs(auth[i].resource->data_len);j++)
                                        auth[i].rdata[j]=reader[j];

                                auth[i].rdata[ntohs(auth[i].resource->data_len)]='\0';
                                reader+=ntohs(auth[i].resource->data_len);
                        }
                        else						/*read name*/
                        {
                                auth[i].rdata=ReadName(reader,buf,&stop);
                                reader+=stop;
                        }

		}

		//read additional
		for(i=0;i<ntohs(dns->add_count);i++)
		{
			addinfo[i].name=ReadName(reader,buf,&stop);
			reader+=stop;

			addinfo[i].resource=(struct R_DATA*)(reader);
			reader+=sizeof(struct R_DATA);

			if(ntohs(addinfo[i].resource->type)==1)				/*read address*/
			{
				addinfo[i].rdata = (unsigned char*)malloc(ntohs(addinfo[i].resource->data_len));
				for(j=0;j<ntohs(addinfo[i].resource->data_len);j++)
					addinfo[i].rdata[j]=reader[j];

				addinfo[i].rdata[ntohs(addinfo[i].resource->data_len)]='\0';
				reader+=ntohs(addinfo[i].resource->data_len);
			}
			else								/*read name*/
			{
				addinfo[i].rdata=ReadName(reader,buf,&stop);
				reader+=stop;
			}
		}

		//print answers
		printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
		for(i=0 ; i < ntohs(dns->ans_count) ; i++)
		{
			if(ntohs(answers[i].resource->type) == 12)
				printf("Address : %s ",answers[i].name);
			else
				printf("Name : %s ",answers[i].name);
			
			if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
			{
				long *p;
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p); 
				printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
			}
			else if(ntohs(answers[i].resource->type)==5) 
				printf("has alias name : %s",answers[i].rdata);
			else if(ntohs(answers[i].resource->type)==12)
				printf("has domain name :%s",answers[i].rdata);
			printf("\n");
		}

		//print authorities
		printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
		for( i=0 ; i < ntohs(dns->auth_count) ; i++)
		{

			printf("Name : %s ",auth[i].name);
			if(ntohs(auth[i].resource->type)==2)
				printf("has nameserver : %s",auth[i].rdata);
			else if(ntohs(auth[i].resource->type)==6)
				printf("has start of authority : %s",auth[i].rdata);
			else if(ntohs(auth[i].resource->type)==12)
				printf("has domain name : %s",auth[i].rdata);
			printf("\n");
		}

		//print additional resource records
		printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
		for(i=0; i < ntohs(dns->add_count) ; i++)
		{
			printf("Name : %s ",addinfo[i].name);
			if(ntohs(addinfo[i].resource->type)==1)
			{
				long *p;
				p=(long*)addinfo[i].rdata;
				a.sin_addr.s_addr=(*p);
				printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
			}
			printf("\n");
		}
	}
	else
	{
		if(dns->rcode==1)
			printf("The name server was unable to interpret the query\n");
		else if(dns->rcode==2)
			printf("The name server was unable to process this query due to a problem with the name server.\n");
		else if(dns->rcode==3)
			printf("domain name referenced in the query does not exist\n");
		else if(dns->rcode==4)
			printf("The name server does not support the requested kind of query.\n");
		else if(dns->rcode==5)
			printf("The server refused to answer\n");
		else if(dns->rcode==6)
			printf("A name exists when it should not\n");
		else if(dns->rcode==7)
			printf("A resource record set exists that should not\n");
		else if(dns->rcode==8)
			printf("A resource record set that should exist does not\n");
		else if(dns->rcode==9)
			printf("The name server receiving the query is not authoritative for the zone specified\n");
		else if(dns->rcode==10)
			printf("A name specified in the message is not within the zone specified in the message\n");
		else
			printf("Unknown error\n");
	}
	return;
}

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);		/*maximum allowed length is 256*/

	name[0]='\0';

	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152;
			reader = buffer + offset - 1;
			jumped = 1; 
		}
		else
			name[p++]=*reader;
		reader = reader+1;
		if(jumped==0)
			*count = *count + 1;
	}

	name[p]='\0';
	if(jumped==1)
		*count = *count + 1;

	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0';
	return name;
}

void removeDotsFromName(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;		/*replace the dot with the number of characters after it before the next dot*/
			for(;lock<i;lock++) 
				*dns++=host[lock];
			lock++; 
		}
	}
	*dns++='\0';
}
