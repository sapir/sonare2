import capstone


def analyze_func(backend, func):
    print(f"analyzing {func.name} @ {func.start:#x}, size {func.size:#x}")
    arch = backend.get_arch()
    disasm = arch.make_disasm(func.attrs.get("mode"))

    func_bytes = backend.buf_mgr.get_bytes(func.start, func.size)
    for insn in disasm.disasm(func_bytes, func.start):
        backend.asm_lines.add(
            insn.address,
            insn.address + insn.size,
            text=f"{insn.insn_name()} {insn.op_str}")


def analyze_all(backend):
    for func in backend.functions.iter_by_addr():
        analyze_func(backend, func)
