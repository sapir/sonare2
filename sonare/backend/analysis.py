import capstone


def analyze_func(backend, func):
    print(f"analyzing {func.name} @ {func.start:#x}, size {func.size:#x}")
    arch = backend.get_arch()
    func_mode = func.attrs.get("mode")
    for opcode in arch.analyze_opcodes(func.start, func.end, mode=func_mode):
        backend.asm_lines.add(
            opcode["address"],
            opcode["address"] + opcode["size"],
            text=opcode["text"],
            flow=opcode["flow"],
            operands=opcode["operands"],
            tokens=opcode["tokens"],
        )


def analyze_all(backend):
    for func in backend.functions.iter_by_addr():
        analyze_func(backend, func)
