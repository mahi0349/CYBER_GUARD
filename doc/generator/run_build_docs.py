"""
Master Runner for QuantumVault Documentation Generation
Executes DocBuilder and stitches all 36 sections together.
"""
import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_docs import DocBuilder
from doc_sections_1_to_8 import add_sections_1_to_8
from doc_sections_9_to_16 import add_sections_9_to_16
from doc_sections_17_to_24 import add_sections_17_to_24
from doc_sections_25_to_36 import add_sections_25_to_36

def main():
    print("=" * 70)
    print("QUANTUMVAULT COMPLETE 36-SECTION DOCUMENTATION GENERATOR")
    print("=" * 70)

    builder = DocBuilder()

    print("[*] Building Sections 1 to 8 (Cover, Control, TOC, Executive Summary, Scope)...")
    add_sections_1_to_8(builder)

    print("[*] Building Sections 9 to 16 (Tech Stack, Architecture, Modules, UI, Scanning)...")
    add_sections_9_to_16(builder)

    print("[*] Building Sections 17 to 24 (APIs, Database, Data Flow, Config, Install, Testing)...")
    add_sections_17_to_24(builder)

    print("[*] Building Sections 25 to 36 (Error Handling, Performance, Guides, Appendix)...")
    add_sections_25_to_36(builder)

    print("[*] Writing and serializing Word document (.docx) and Markdown (.md)...")
    builder.save()

    print("=" * 70)
    print("DOCUMENTATION GENERATION COMPLETE!")
    print(f"Output files in doc/:")
    print(f"  - doc/Quantum_Vault_Complete_Documentation.docx")
    print(f"  - doc/Quantum_Vault_Complete_Documentation.md")
    print("=" * 70)

if __name__ == "__main__":
    main()
