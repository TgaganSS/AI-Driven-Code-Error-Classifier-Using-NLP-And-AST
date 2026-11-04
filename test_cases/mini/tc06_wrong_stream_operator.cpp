// TC-06 | Category: type_error (stream operator mismatch)
// Error : 'cin' used with '<<' instead of '>>' (output operator on input stream).
// The auto-healer should flip the operator direction.

#include <iostream>
using namespace std;

int main() {
    int age;
    cout << "Enter your age: ";
    cin << age;           // Wrong: should be cin >> age
    cout << "You are " << age << " years old." << endl;
    return 0;
}
