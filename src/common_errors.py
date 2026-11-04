COMMON_ERRORS = [
  {
    "message": "expected ';' before 'int'",
    "category": "syntax_error",
    "ast_node": "NullStmt",
    "explanation": "A statement is missing its terminating semicolon. The compiler found the next token before the expected ';'.",
    "suggestion": "Add ';' at the end of the statement",
    "confidence": 1.0
  },
  {
    "message": "lvalue required as left operand of assignment",
    "category": "syntax_error",
    "ast_node": "BinaryOperator",
    "explanation": "An assignment '=' is used where a comparison '==' was intended inside a condition. This assigns rather than compares, often evaluating as always true.",
    "suggestion": "Replace '=' with '==' inside the if condition",
    "confidence": 0.9
  },
  {
    "message": "'x' was not declared in this scope",
    "category": "name_resolution",
    "ast_node": "DeclRefExpr",
    "explanation": "The variable 'x' is being used before it has been declared. In C++, variables must be declared before use.",
    "suggestion": "Declare the variable before using it, e.g. 'int x = 10;'",
    "confidence": 1.0
  },
  {
    "message": "'cout' was not declared in this scope",
    "category": "missing_include",
    "ast_node": "DeclRefExpr",
    "explanation": "The identifier 'cout' is unavailable because the <iostream> header has not been included.",
    "suggestion": "Add '#include <iostream>' at the top of your file",
    "confidence": 1.0
  },
  {
    "message": "ISO C++ forbids declaration of 'main' with no type",
    "category": "syntax_error",
    "ast_node": "FunctionDecl",
    "explanation": "The 'main' function must have a return type of 'int'. Omitting the return type is not valid in standard C++.",
    "suggestion": "Change 'main()' to 'int main()'",
    "confidence": 1.0
  },
  {
    "message": "variable 'i' used in loop condition is never modified",
    "category": "other",
    "ast_node": "WhileStmt",
    "explanation": "The loop condition references a variable that is never updated inside the loop body, causing an infinite loop.",
    "suggestion": "Add an increment or update statement inside the loop, e.g. 'i++'",
    "confidence": 0.9
  },
  {
    "message": "array subscript is above array bounds",
    "category": "other",
    "ast_node": "ArraySubscriptExpr",
    "explanation": "The loop runs one iteration too many due to using '<=' instead of '<', causing an off-by-one access beyond the array.",
    "suggestion": "Change '<=' to '<' in the loop condition",
    "confidence": 0.95
  },
  {
    "message": "conversion from 'double' to 'float' may lose precision",
    "category": "type_error",
    "ast_node": "ImplicitCastExpr",
    "explanation": "Integer division of 5/2 yields 2, not 2.5. The result is an integer before being assigned to the float.",
    "suggestion": "Use '5.0/2' or 'static_cast<float>(5)/2' to force floating-point division",
    "confidence": 0.9
  },
  {
    "message": "'x' is used uninitialized in this function",
    "category": "other",
    "ast_node": "DeclRefExpr",
    "explanation": "The variable 'x' was declared but never assigned a value before use. Reading it produces undefined garbage.",
    "suggestion": "Initialize the variable at declaration, e.g. 'int x = 0;'",
    "confidence": 1.0
  },
  {
    "message": "condition is always false",
    "category": "other",
    "ast_node": "BinaryOperator",
    "explanation": "The condition combines two contradictory constraints that can never both be true simultaneously, making the branch unreachable.",
    "suggestion": "Review the logic — check whether '&&' should be '||' or if the comparison operators are correct",
    "confidence": 0.85
  },
  {
    "message": "null pointer dereference",
    "category": "other",
    "ast_node": "UnaryOperator",
    "explanation": "A NULL or nullptr pointer is being dereferenced. Accessing memory through a null pointer causes a segmentation fault.",
    "suggestion": "Check that the pointer is not NULL before dereferencing, or initialize it to a valid address",
    "confidence": 1.0
  },
  {
    "message": "array subscript out of bounds",
    "category": "other",
    "ast_node": "ArraySubscriptExpr",
    "explanation": "An array of size 5 has valid indices 0 through 4. Accessing index 5 reads or writes beyond allocated memory.",
    "suggestion": "Ensure loop indices and accesses stay within 0 to array_size-1",
    "confidence": 1.0
  },
  {
    "message": "infinite recursion detected",
    "category": "other",
    "ast_node": "CallExpr",
    "explanation": "The function calls itself unconditionally with no base case, causing the call stack to overflow at runtime.",
    "suggestion": "Add a base case that stops the recursion, e.g. 'if (n <= 0) return;'",
    "confidence": 0.95
  },
  {
    "message": "division by zero",
    "category": "other",
    "ast_node": "BinaryOperator",
    "explanation": "An integer is being divided by zero, which is undefined behavior in C++ and causes a runtime crash.",
    "suggestion": "Check that the divisor is not zero before performing division",
    "confidence": 1.0
  },
  {
    "message": "use after free of pointer",
    "category": "other",
    "ast_node": "UnaryOperator",
    "explanation": "The pointer is being dereferenced after the memory it points to has been freed with 'delete'. This is undefined behavior.",
    "suggestion": "Set the pointer to nullptr immediately after deleting it, e.g. 'delete p; p = nullptr;'",
    "confidence": 1.0
  },
  {
    "message": "memory leak: allocated memory is never freed",
    "category": "other",
    "ast_node": "CXXNewExpr",
    "explanation": "Memory allocated with 'new' is never released with 'delete', causing a memory leak for the lifetime of the program.",
    "suggestion": "Add a matching 'delete p;' when done, or use smart pointers like std::unique_ptr",
    "confidence": 0.95
  },
  {
    "message": "double free or corruption of pointer",
    "category": "other",
    "ast_node": "CXXDeleteExpr",
    "explanation": "The same pointer is being deleted twice. After the first delete, the pointer is invalid and deleting it again corrupts the heap.",
    "suggestion": "Set the pointer to nullptr after the first delete so subsequent deletes are no-ops",
    "confidence": 1.0
  },
  {
    "message": "invalid conversion from 'int' to 'int*'",
    "category": "type_error",
    "ast_node": "ImplicitCastExpr",
    "explanation": "An integer value is being assigned directly to a pointer. A pointer must hold a memory address, not a raw value.",
    "suggestion": "Use '&x' to get the address of x, e.g. 'int* p = &x;'",
    "confidence": 1.0
  },
  {
    "message": "'vector' was not declared in this scope",
    "category": "missing_header",
    "ast_node": "TypeRef",
    "explanation": "The type 'vector' is unavailable because the <vector> header has not been included.",
    "suggestion": "Add '#include <vector>' at the top of your file",
    "confidence": 1.0
  },
  {
    "message": "iterator invalidated by erase",
    "category": "other",
    "ast_node": "CXXMemberCallExpr",
    "explanation": "After calling erase() on a container, the iterator pointing to the erased element becomes invalid. Dereferencing it is undefined behavior.",
    "suggestion": "Use the iterator returned by erase(), e.g. 'it = v.erase(it);'",
    "confidence": 0.95
  },
  {
    "message": "calling top() on empty container",
    "category": "other",
    "ast_node": "CXXMemberCallExpr",
    "explanation": "Calling top() or front() on an empty container is undefined behavior and causes a runtime crash.",
    "suggestion": "Check '!s.empty()' before calling top() or front()",
    "confidence": 1.0
  },
  {
    "message": "getline skips input after formatted extraction",
    "category": "other",
    "ast_node": "CallExpr",
    "explanation": "After 'cin >> x', a newline remains in the input buffer. The subsequent getline() reads that newline and returns an empty string.",
    "suggestion": "Add 'cin.ignore()' after 'cin >> x' to flush the leftover newline before calling getline",
    "confidence": 0.9
  },
  {
    "message": "'cout' is not a member of 'std'",
    "category": "name_resolution",
    "ast_node": "DeclRefExpr",
    "explanation": "The identifier 'cout' is in the std namespace and must be qualified with 'std::' or brought into scope with 'using namespace std;'.",
    "suggestion": "Use 'std::cout' or add 'using namespace std;' after your includes",
    "confidence": 1.0
  },
  {
    "message": "parameter 'x' is passed by value; changes will not affect the caller",
    "category": "other",
    "ast_node": "ParmVarDecl",
    "explanation": "The function receives a copy of the variable. Any modifications inside the function do not affect the original variable in the caller.",
    "suggestion": "Change the parameter to a reference: 'void f(int &x)' to allow the function to modify the caller's variable",
    "confidence": 0.95
  },
  {
    "message": "assignment of read-only variable 'x'",
    "category": "type_error",
    "ast_node": "BinaryOperator",
    "explanation": "A variable declared as 'const' cannot be modified after initialization. Assigning to it violates its const guarantee.",
    "suggestion": "Remove the 'const' qualifier if the variable needs to change, or do not assign to it after initialization",
    "confidence": 1.0
  }
]
