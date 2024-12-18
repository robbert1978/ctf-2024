#include <stdint.h>


union DWORD
{
    uint32_t u;
    int32_t i;
};

int main() {
    union DWORD x;
    x = (uint32_t)3;

}

