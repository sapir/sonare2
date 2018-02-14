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
            "address": addr,
            "size": len(insn_bytes),
            "text": code,
        })

    return lines


class AvrArch(BaseArch):
    def __init__(self, backend):
        super().__init__(backend)

    def hook_post_load_file(self, filename, loader_type):
        assert loader_type == "elf"

        for line in disassemble_objdump(filename):
            self.backend.asm_lines.upsert(
                line["address"],
                line["address"] + line["size"],
                text=line["text"],
            )

    # TODO: analyze_opcodes
