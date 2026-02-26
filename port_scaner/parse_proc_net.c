#include "port_scanner.h"

/**
 * parse_proc_net - Reads and parses network tables from the /proc filesystem
 * @file_path: The path to the file to parse (e.g., /proc/net/tcp)
 * @protocol: String representing the protocol being parsed ("TCP" or "UDP")
 *
 * Description: Reads the specified /proc file line by line, extracting the
 * local IP, port, connection state, and inode for active listening sockets.
 * Populates the global `ports` array.
 * Return: void
 */
void parse_proc_net(const char *file_path, const char *protocol)
{
    /* fp: File pointer for opening the /proc/net file */
    FILE *fp = fopen(file_path, "r");
    /* line: Buffer to hold each line read from the file */
    char line[512];

    if (!fp)
    {
        perror("Failed to open /proc file");
        return;
    }

    fgets(line, sizeof(line), fp); /* Skip header line */

    while (fgets(line, sizeof(line), fp))
    {
        /* local_ip_hex, local_port_hex, state: Variables to hold hex values from the file */
        unsigned int local_ip_hex, local_port_hex, state;
        /* inode: Unique socket identifier used to map to the owning process */
        unsigned long inode;
        
        if (sscanf(line, "%*d: %X:%X %*X:%*X %X %*X:%*X %*X:%*X %*X %*d %*d %lu", 
                   &local_ip_hex, &local_port_hex, &state, &inode) == 4)
        {
            if ((strcmp(protocol, "TCP") == 0 && state == 0x0A) || strcmp(protocol, "UDP") == 0)
            {
                /* p: Pointer to the next available struct in the global ports array */
                PortInfo *p;
                /* ip_addr: Structure used to convert the hex IP into standard format */
                struct in_addr ip_addr;
                /* serv: Structure returned by getservbyport containing service details */
                struct servent *serv;

                if (port_count >= MAX_PORTS)
                    break;
                
                p = &ports[port_count];
                strcpy(p->protocol, protocol);
                p->port = local_port_hex;
                p->inode = inode;
                p->is_high_interest = check_high_interest(p->port);

                ip_addr.s_addr = local_ip_hex;
                strcpy(p->local_ip, inet_ntoa(ip_addr));

                set_risk_label(p->local_ip, p->risk_label);

                serv = getservbyport(htons(p->port), strtolower(protocol));
                if (serv)
                    strcpy(p->service_name, serv->s_name);
                else
                    strcpy(p->service_name, "-");

                find_process_by_inode(p->inode, &p->pid, p->process_name);

                port_count++;
            }
        }
    }
    fclose(fp);
}
