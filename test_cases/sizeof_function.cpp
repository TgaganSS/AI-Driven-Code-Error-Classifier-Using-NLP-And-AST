#include <iostream>
using namespace std;

int foo(int x) {
    return x;
}

int main() {
    int s = sizeof(foo);
    return 0;
}
