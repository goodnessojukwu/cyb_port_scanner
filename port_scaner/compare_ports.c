#include "port_scanner.h"

/**
 * compare_ports - Comparison function used for qsort
 * @a: Pointer to the first PortInfo struct to compare
 * @b: Pointer to the second PortInfo struct to compare
 *
 * Description: Sorts ports primarily alphabetically by protocol (TCP/UDP),
 * and secondarily by the port number in ascending numerical order.
 * Return: An integer less than, equal to, or greater than zero if the first
 * argument is considered respectively less than, equal to, or greater than
 * the second.
 */
int compare_ports(const void *a, const void *b)
{
    /* p1, p2: Pointers casted back to PortInfo type to access struct members */
    PortInfo *p1 = (PortInfo *)a;
    PortInfo *p2 = (PortInfo *)b;
    /* proto_cmp: Integer holding the result of the protocol string comparison */
    int proto_cmp = strcmp(p1->protocol, p2->protocol);

    if (proto_cmp != 0)
        return (proto_cmp);
        
    return (p1->port - p2->port);
}
