# SMDA

[![x86_64](https://github.com/marirs/smda-rs/actions/workflows/linux_x86-64.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/linux_x86-64.yml)
[![Arm7](https://github.com/marirs/smda-rs/actions/workflows/linux_arm7.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/linux_arm7.yml)
[![Windows](https://github.com/marirs/smda-rs/actions/workflows/windows.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/windows.yml)
[![macOS](https://github.com/marirs/smda-rs/actions/workflows/macos.yml/badge.svg)](https://github.com/marirs/smda-rs/actions/workflows/macos.yml)

SMDA is a minimalist recursive disassembler library that is 
optimized for accurate Control Flow Graph (CFG) recovery 
from memory dumps. It is based on Capstone and currently 
supports x86/x64 Intel machine code. As input, arbitrary 
memory dumps (ideally with known base address) can be processed. 

The output is a collection of functions, basic blocks, 
and instructions with their respective edges between blocks and 
functions (in/out). Optionally, references to the Windows API 
can be inferred by using the ApiScout method.

### Requirements
- Rust 1.56+ (edition 2021)

---
LICENSE: MIT