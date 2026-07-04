#include <stdio.h>
#include <unistd.h>

int add(int a, int b)
{
    int c = a + b;
    return c;
}

int main()
{
    int x = 10;
    int y = 20;

    while (1) {

        int z = add(x, y);

        printf("result=%d\n", z);

        sleep(1);
    }

    return 0;
}
