// TC-03 | Category: missing_include
// Error : 'vector' is not declared — #include <vector> is absent.
// The auto-healer should insert the correct #include directive.

#include <iostream>
using namespace std;

int main() {
    vector<int> numbers = {1, 2, 3, 4, 5};
    for (int n : numbers) {
        cout << n << " ";
    }
    cout << endl;
    return 0;
}
