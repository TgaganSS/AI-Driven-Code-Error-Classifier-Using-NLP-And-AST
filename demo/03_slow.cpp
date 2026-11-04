#include <iostream>
#include <string>
#include <vector>
#include <cstring>

int fib(int n) { if (n < 2) return n; return fib(n - 1) + fib(n - 2); }   // exponential

int count_a(const char* s) {
    int c = 0;
    for (size_t i = 0; i < strlen(s); i++) if (s[i] == 'a') c++;           // hidden O(n^2)
    return c;
}

int total(std::vector<int> v) {                                            // copies the vector
    int s = 0;
    for (int x : v) s += x;
    return s;
}

int main() {
    int n;
    std::cin >> n;
    for (int i = 0; i < n; i++) std::cout << i << std::endl;               // flush every line
    std::cout << fib(20) << count_a("banana") << total({1, 2, 3});
}
