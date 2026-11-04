// Clean baseline for the security analyzer: the analyzer should report
// ZERO findings on this file. (test_secure.cpp is, despite its name, a
// deliberately vulnerable sample and is expected to produce findings.)
#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

// Bounds-checked storage instead of raw arrays
bool storeScore(std::vector<int>& scores, std::size_t index, int value) {
    if (index >= scores.size()) {
        return false;
    }
    scores[index] = value;
    return true;
}

// Owning smart pointer: no manual new/delete
std::unique_ptr<std::vector<int>> createBuffer(std::size_t size) {
    auto buffer = std::make_unique<std::vector<int>>(size);
    for (std::size_t i = 0; i < size; ++i) {
        (*buffer)[i] = static_cast<int>(i) * 2;
    }
    return buffer;
}

// Cryptographically-seeded generator instead of rand()/srand()
unsigned int generateToken() {
    std::random_device rd;
    std::mt19937 gen(rd());
    return gen();
}

std::optional<int> parsePositive(const std::string& text) {
    try {
        int v = std::stoi(text);
        if (v > 0) {
            return v;
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

int main() {
    std::vector<int> scores(5, 0);
    storeScore(scores, 2, 42);

    auto buf = createBuffer(4);
    std::cout << "buffer size: " << buf->size() << "\n";
    std::cout << "token generated: " << (generateToken() != 0) << "\n";

    if (auto n = parsePositive("17")) {
        std::cout << "parsed: " << *n << "\n";
    }
    return 0;
}
