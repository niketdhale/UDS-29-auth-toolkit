#include <Uds29.h>
#include <stdio.h>

int main(void) {
    Uds29_ConfigType cfg = {0x00, 32};
    Std_ReturnType r = Uds29_Init(&cfg);
    printf("Uds29_Init -> %d, state %d\n", r, (int)Uds29_GetState());
    Uds29_DeInit();
    return r == E_OK ? 0 : 1;
}
