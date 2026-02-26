#include "port_scanner.h"

/**
 * strtolower - Converts a given string to lowercase
 * @str: The input string (usually a protocol like "TCP")
 *
 * Description: Safely converts the characters of a string to lowercase
 * to be used with network mapping functions like getservbyport.
 * Return: A pointer to a static string containing the lowercase result.
 */
char *strtolower(const char *str)
{
    /* lower: A static buffer to hold the resulting lowercase string */
    static char lower[4];
    /* i: Loop counter to iterate through characters of the input string */
    int i;

    for (i = 0; str[i]; i++)
    {
        lower[i] = tolower(str[i]);
    }
    lower[strlen(str)] = '\0';
    
    return (lower);
}
