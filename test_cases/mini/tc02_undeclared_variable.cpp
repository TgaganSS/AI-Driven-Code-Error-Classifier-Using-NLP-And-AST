// TC-02 | Category: name_resolution
// Error : Variable 'result' is used before it is declared.
// The auto-healer should insert 'auto result = ...' before the first use.

#include <iostream>
using namespace std;

int main() {
    int a = 5;
    int b = 3;
    result = a + b;
    cout << "Result: " << result << endl;
    return 0;
}
