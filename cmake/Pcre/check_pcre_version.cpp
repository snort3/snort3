#include <pcre.h>

#if (PCRE_MAJOR < 6)
#error "Version failure."
#else
int main(void)
{
    int a, b = 0, c = 0, d = 0;
    pcre *tmp = NULL;
    a = pcre_copy_named_substring(tmp, "", &b, c, "", "", d);
}
#endif
