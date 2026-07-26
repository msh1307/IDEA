#include <stddef.h>

__attribute__((noinline, used))
int replay_target(const unsigned char *input, size_t length) {
    unsigned first = length > 0 ? input[0] : 0;
    unsigned second = length > 1 ? input[1] : 0;
    if ((first ^ second) == 0x5a)
        return 0x1337;
    return (int)(first * 3u + second);
}

int main(void) {
    static const unsigned char input[] = {0, 0};
    return replay_target(input, sizeof(input));
}
