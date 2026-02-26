#include "port_scanner.h"

/* Define global variables here */
PortInfo ports[MAX_PORTS];
int port_count = 0;
int high_interest_ports[] = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389};
int num_high_interest = 12;

/**
 * main - Entry point for the port scanner program
 *
 * Description: Initializes the scanning process, sorts the discovered ports,
 * outputs the table to standard output, and generates a text file report.
 * Return: 0 upon successful execution, 1 on file error.
 */
int main(void)
{
    /* out_file: File pointer used to generate the report text file */
    FILE *out_file;
    /* header_format: A formatting string used to align table columns cleanly */
    const char *header_format = "%-5s | %-6s | %-15s | %-12s | %-6s | %-15s | %-12s | %s\n";
    /* high_interest_found: Counter tracking the number of exposed high risk ports */
    int high_interest_found = 0;
    /* i: Loop counter to iterate over the populated ports array */
    int i;

    printf("Scanning /proc/net for listening ports...\n");

    parse_proc_net(PROC_TCP, "TCP");
    parse_proc_net(PROC_UDP, "UDP");

    qsort(ports, port_count, sizeof(PortInfo), compare_ports);

    out_file = fopen("ports_report.txt", "w");
    if (!out_file)
    {
        perror("Failed to create report file");
        return (1);
    }

    printf("\n");
    printf(header_format, "PROTO", "PORT", "LOCAL ADDRESS", "SERVICE", "PID", "PROCESS", "RISK", "FLAG");
    printf("--------------------------------------------------------------------------------------------------------\n");
    fprintf(out_file, header_format, "PROTO", "PORT", "LOCAL ADDRESS", "SERVICE", "PID", "PROCESS", "RISK", "FLAG");
    fprintf(out_file, "--------------------------------------------------------------------------------------------------------\n");

    for (i = 0; i < port_count; i++)
    {
        /* p: Pointer to the current port structure being processed */
        PortInfo *p = &ports[i];
        /* pid_str: Buffer to format the Process ID or "Deny" if permissions failed */
        char pid_str[16];
        /* flag_str: Buffer to hold the optional "[HIGH RISK]" tag */
        char flag_str[16] = "";

        if (p->pid == -1)
            strcpy(pid_str, "Deny"); 
        else
            snprintf(pid_str, sizeof(pid_str), "%d", p->pid);

        if (p->is_high_interest)
        {
            strcpy(flag_str, "[HIGH RISK]");
            high_interest_found++;
        }

        printf("%-5s | %-6d | %-15s | %-12s | %-6s | %-15s | %-12s | %s\n",
               p->protocol, p->port, p->local_ip, p->service_name, pid_str, p->process_name, p->risk_label, flag_str);
        
        fprintf(out_file, "%-5s | %-6d | %-15s | %-12s | %-6s | %-15s | %-12s | %s\n",
                p->protocol, p->port, p->local_ip, p->service_name, pid_str, p->process_name, p->risk_label, flag_str);
    }

    printf("\n--- SUMMARY ---\n");
    printf("Total Listening Ports: %d\n", port_count);
    printf("High-Interest Ports Exposed: %d\n", high_interest_found);
    printf("Output saved to ports_report.txt\n");

    fprintf(out_file, "\n--- SUMMARY ---\n");
    fprintf(out_file, "Total Listening Ports: %d\n", port_count);
    fprintf(out_file, "High-Interest Ports Exposed: %d\n", high_interest_found);

    fclose(out_file);
    return (0);
}
