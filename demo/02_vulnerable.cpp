#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
using namespace std;

void greet(const char* name) {
    char buf[8];
    strcpy(buf, name);               // CWE-120 buffer overflow (attacker-controlled)
    printf("hello %s\n", buf);
}

void log_line(const char* msg) {
    printf(msg);                     // CWE-134 format string
}

void table() {
    int t[10];
    int i;
    cin >> i;
    t[i] = 1;                        // CWE-129 unvalidated index from user input
}

int main(int argc, char** argv) {
    if (argc > 1) { greet(argv[1]); log_line(argv[1]); }
    int* p = new int[4];
    delete p;                        // CWE-762 new[] released with delete
    char* q = (char*)malloc(8);
    if (!q) return 1;
    free(q);
    free(q);                         // CWE-415 double free
    return 0;
}
