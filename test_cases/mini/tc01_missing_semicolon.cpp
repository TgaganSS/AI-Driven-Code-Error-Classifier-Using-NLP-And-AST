// TC-01 | Category: syntax_error
// Error : Missing semicolon after variable declaration.
// The auto-healer should insert ';' and recompile cleanly.

#include <iostream>
using namespace std;

int main() {
    int x = 10
    int y = 20;
    cout << "Sum = " << x + y << endl;
    return 0;
}
