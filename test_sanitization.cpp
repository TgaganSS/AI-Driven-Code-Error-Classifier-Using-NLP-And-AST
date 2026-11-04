#include <iostream>
#include <cstdlib>

int main() {
    system("echo hello");

    system("rm -rf /tmp/test");

    char cmd[] = "ls";
    system(cmd);

    FILE* f = popen("whoami", "r");
    pclose(f);

    __asm__("nop");

    return 0;
}