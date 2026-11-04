import sys
sys.path.insert(0, 'src')
from heal_loop import HealWorker
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QCoreApplication

app = QCoreApplication([])

class _MockClassifier:
    def predict(self, msg, ast=""): return "syntax_error", 1.0

worker = HealWorker("test_heal.cpp", _MockClassifier())
def print_diff(attempt, diff_html): print(f"--- Attempt {attempt} Diff ---")
def compile_clean(): print("SUCCESS")

worker.diff_ready.connect(print_diff)
worker.compile_clean.connect(compile_clean)
worker._heal()
