#include "port_scanner.h"

/**
 * check_high_interest - Checks if a given port is in the high-interest list
 * @port: The integer port number to evaluate
 *
 * Description: Iterates through the global array of high_interest_ports
 * to see if the given port matches any of them.
 * Return: 1 if the port is considered high interest, 0 otherwise.
 */
int check_high_interest(int port)
{
    /* i: Loop counter to iterate through the high_interest_ports array */
    int i;

    for (i = 0; i < num_high_interest; i++)
    {
        if (port == high_interest_ports[i])
            return (1);
    }
    return (0);
}
