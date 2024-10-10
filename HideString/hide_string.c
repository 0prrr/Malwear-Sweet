#include <windows.h>
#include <stdio.h>

void c_str(char *buf, size_t size, ...)
{
    buf[0] = '\0';

    va_list args;
    va_start(args, size);

    char arg = va_arg(args, int);
    size_t len = 0;

    while (arg && len < size - 1)
    {
        buf[len++] = arg;
        arg = va_arg(args, int);
    }

    buf[len] = '\0';
    va_end(args);
}

int main()
{
    BOOL is_success = TRUE;
    char my_str[12];
    c_str(my_str, sizeof(my_str), 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '\0');
    printf("%s\n", my_str);

    return 0;
}

