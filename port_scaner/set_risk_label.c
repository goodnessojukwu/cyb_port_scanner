#include "port_scanner.h"

/**
 * set_risk_label - Assigns a security risk label based on the bound IP address
 * @ip: A string representing the local IP address the port is bound to
 * @label: A pre-allocated string buffer where the resulting label is stored
 *
 * Description: Evaluates the IP string and assigns "Exposed" for 0.0.0.0/::,
 * "Local-only" for loopback addresses, or "Specific-IP" for others.
 * Return: void
 */
void set_risk_label(const char *ip, char *label)
{
    if (strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "::") == 0)
    {
        strcpy(label, "Exposed");
    }
    else if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0)
    {
        strcpy(label, "Local-only");
    }
    else
    {
        strcpy(label, "Specific-IP");
    }
}
