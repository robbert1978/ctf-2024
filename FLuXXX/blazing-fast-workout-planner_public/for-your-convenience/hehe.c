#include <stdio.h>
#include <unistd.h>


int main(){

    int (*f)(void) = &&hehe;

    f();

    puts("Never reached");

hehe:

    write(1, "OKE\n", 4);
    _exit(0);
}