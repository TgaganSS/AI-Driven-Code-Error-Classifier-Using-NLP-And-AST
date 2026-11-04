// TC-08 | Category: integer_overflow
// Warning: 'count' is set to INT_MAX and then incremented — overflow is certain.
// The pre-scan detects this before compilation and the healer widens to long long.

#include <iostream>
#include <climits>
using namespace std;

int main() {
    int count = 2147483647;  // INT_MAX
    count++;                 // Overflow!
    cout << "Count: " << count << endl;
    return 0;
}
