#include <stdlib.h>
void srand(uint __seed)

{
    undefined *puVar1;
    undefined4 *puVar2;
    int iVar3;

    puVar1 = _impure_ptr;
    gp = &__global_pointer$;
    if (*(int *)(_impure_ptr + 0x38) == 0)
    {
        puVar2 = (undefined4 *)malloc(0x18);
        *(undefined4 **)(puVar1 + 0x38) = puVar2;
        *puVar2 = 0xabcd330e;
        puVar2[1] = 0xe66d1234;
        puVar2[2] = 0x5deec;
        *(undefined2 *)(puVar2 + 3) = 0xb;
        puVar2[4] = 1;
        puVar2[5] = 0;
    }
    iVar3 = *(int *)(puVar1 + 0x38);
    *(uint *)(iVar3 + 0x10) = __seed;
    *(undefined4 *)(iVar3 + 0x14) = 0;
    return;
}