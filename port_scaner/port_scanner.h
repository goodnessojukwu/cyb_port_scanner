#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <string.h>


#define MAX_PORTS 1024
#define PROC_TCP "/proc/net/tcp"
#define PROC_UDP "/proc/net/udp"


typedef struct{
	char protocol[4];
	char local_ip[64];
	int port;
	unsigned long inode;
	int pid;
	char process_name[256];
	char service_name[64];
	char risk_label[32];
	int is_high_interest;
}PortInfo;

// Extern declarations for global variables (defined in main.c)
extern PortInfo ports[MAX_PORTS];
extern int port_count;
extern int high_interest_ports[];
extern int num_high_interest;

// Functions
int check_high_interest(int port);
void set_risk_label(const char *ip, char *label);
void find_process_by_inode(unsigned long target_inode, int *out_pid, char *out_comm);
void parse_proc_net(const char *file_path, const char *protocol);
int compare_ports(const void *a, const void *b);
char* strtolower(const char* str);

#endif /* PORT_SCANNER_H */
