import re
from binascii import unhexlify
from subprocess import check_output
from .base import BaseArch


def disassemble_objdump(filename):
    # TODO: only objdump proper sections. then again, we should really run
    # integrated disassembly code rather than objdump :)
    disasm = check_output(["avr-objdump", "-D", filename])
    disasm = disasm.decode("ascii")

    lines = []

    for addr_str, insn_bytes, code in re.findall(
            r'(?m)^\s*([0-9a-f]+):\s+([0-9a-f ]+)\t([^;\n]+)(?:;|$)', disasm):

        addr = int(addr_str, 16)
        insn_bytes = unhexlify(insn_bytes.replace(" ", ""))
        code = code.strip()
        code = re.sub(r"\s+", " ", code)

        lines.append({
            "start": addr,
            "end": addr + len(insn_bytes),
            "text": code,
        })

    return lines


class AvrArch(BaseArch):
    def __init__(self, backend):
        super().__init__(backend)

    def hook_post_load_file(self, filename, loader_type):
        assert loader_type == "elf"

        raw_asm_lines = disassemble_objdump(filename)
        for line in raw_asm_lines:
            self.backend.asm_lines.upsert(
                line["start"],
                line["end"],
                text=line["text"],
            )

        # assume functions start on lines following "ret" and mark them all
        # TODO: also interrupt vectors
        func_starts = [0]
        func_starts += [
            line["end"] for line in raw_asm_lines
            if line["text"] == "ret"
        ]

        # let last function end at end of file = last_line_end
        last_line_end = raw_asm_lines[-1]["end"]
        for func_start, next_func_start in zip(
                func_starts, func_starts[1:] + [last_line_end]):

            self.backend.functions.add(
                func_start,
                next_func_start,
                name=f"func_{func_start:x}")

    # TODO: analyze_opcodes
