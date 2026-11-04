#include <iostream>
int main() {
    int* p = nullptr;
    *p = 10;              // the OLD tool said "Compilation successful, risk: Clean"
    return 0;
}
