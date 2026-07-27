/*
 * Fixture for 04_テスト仕様書.md T-101 (構造体メンバ上限): a struct with
 * more members (20) than tdb's type_info_t.members[16] can track.
 */
#include <stdio.h>

struct big {
    int m1, m2, m3, m4, m5, m6, m7, m8, m9, m10;
    int m11, m12, m13, m14, m15, m16, m17, m18, m19, m20;
};

int main(void)
{
    struct big b;
    int i;
    int *p = (int *)&b;

    for (i = 0; i < 20; i++)
        p[i] = i + 1;

    printf("sum=%d\n", b.m1 + b.m20);
    return 0;
}
