/*
 * Fixture for 04_テスト仕様書.md T-102 (ヒープ確保記録上限): allocates
 * more times (4200) than tdb's heap.c MAX_HEAP_ALLOCS (4096) can track.
 * Intentionally leaks everything (never frees) so each allocation stays
 * live long enough to be counted by `show leaks`.
 */
#include <stdlib.h>
#include <stdio.h>

#define COUNT 4200

int main(void)
{
    int i;
    void *p;

    for (i = 0; i < COUNT; i++) {
        p = malloc(8);
        if (!p) {
            fprintf(stderr, "allocation %d failed\n", i);
            return 1;
        }
    }

    printf("done: allocated %d times\n", COUNT);
    return 0;
}
