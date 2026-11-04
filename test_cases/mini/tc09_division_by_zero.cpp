// TC-09 | Category: division_by_zero
// Warning: Literal 0 is used as a divisor.
// The pre-scan detects this and the healer wraps the division in a guard.

#include <iostream>
using namespace std;

int main() {
    int dividend = 100;
    int divisor = 0;
    int result = dividend / divisor;  // Division by zero
    cout << "Result: " << result << endl;
    return 0;
}
