// TC-04 | Category: uninitialized_memory
// Warning : 'total' may be used uninitialized.
// The auto-healer should initialize 'total' to 0 at its declaration.

#include <iostream>
using namespace std;

int main() {
    int total;
    int values[5] = {10, 20, 30, 40, 50};
    for (int i = 0; i < 5; i++) {
        total += values[i];
    }
    cout << "Total: " << total << endl;
    return 0;
}
