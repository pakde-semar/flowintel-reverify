"""
Quick smoke test for the reverify_binary Flowintel module.
Run from repo root: python tests/test_module.py [/path/to/binary]
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyze.reverify_binary import handler, introspection

# Minimal fake case/user/instance
FAKE_CASE = {
    "id": 1, "title": "Test Case",
    "tasks": [], "objects": [],
}
FAKE_USER     = {"id": 1, "email": "test@test.com"}
FAKE_INSTANCE = {}

def run(binary_path: str, depth: str = "quick"):
    print(f"\n{'='*60}")
    print(f"Testing reverify_binary module")
    print(f"Binary : {binary_path}")
    print(f"Depth  : {depth}")
    print("="*60)

    result = handler(
        instance=FAKE_INSTANCE,
        case=FAKE_CASE,
        user=FAKE_USER,
        payload={"file_path": binary_path, "depth": depth},
    )

    if "message" in result:
        print(f"ERROR : {result['message']}")
        return

    print(result["summary"])
    print(f"\nSections : {result['findings']['sections'][:5]}")
    print(f"Imports  : {result['findings']['imports'][:5]}")
    print(f"Strings  : {result['findings']['strings'][:3]}")

    if depth == "full" and "disasm_entry" in result["findings"]:
        print("\nEntry point disasm (first 5 instructions):")
        for instr in result["findings"]["disasm_entry"][:5]:
            if "error" not in instr:
                print(f"  {instr['address']}  {instr['mnemonic']:<10} {instr['op_str']}")

    print(f"\nSuspicious strings: {result['findings'].get('suspicious_count', 'n/a')}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
    depth  = sys.argv[2] if len(sys.argv) > 2 else "full"
    print("Module introspection:", introspection())
    run(target, depth)
