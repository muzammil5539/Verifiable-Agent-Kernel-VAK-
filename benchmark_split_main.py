import time
import timeit
from examples.code_auditor_python import CodeAuditor

# Create a large dummy payload
code_lines = [
    'def dangerous_function():',
    '    api_key = "sk-1234567890"',
    '    query = f"SELECT * FROM users WHERE key = {api_key}"',
    '    result = query.execute().unwrap()',
    '    unsafe {',
    '        do_dangerous_thing()',
    '    }',
] * 1000  # 7000 lines
large_payload = "\n".join(code_lines)

auditor = CodeAuditor()

def run_analysis():
    auditor.analyze_file("test_large.rs", large_payload)

if __name__ == "__main__":
    runs = 100
    total_time = timeit.timeit(run_analysis, number=runs)
    avg_time = (total_time / runs) * 1000
    print(f"Average time over {runs} runs: {avg_time:.2f} ms")
