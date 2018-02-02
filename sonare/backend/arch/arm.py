import capstone
from .base import BaseArch


class ArmArch(BaseArch):
    def __init__(self, backend):
        super().__init__(backend)

        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, mode=0)
        self.cs.detail = True

    def hook_load_symbol(self, sym):
        # thumb
        if sym.start & 1:
            sym.start -= 1
            sym.end -= 1
            sym.attrs["mode"] = "thumb"

    def _get_capstone_mode(self, mode):
        cs_mode = capstone.CS_MODE_LITTLE_ENDIAN

        if mode == "thumb":
            cs_mode |= capstone.CS_MODE_THUMB

        return cs_mode

    def analyze_opcodes(self, start, end, mode=None):
        cs_mode = self._get_capstone_mode(mode)

        for insn in self._disassemble(self.cs, cs_mode, start, end):
            yield {
                "address": insn.address,
                "size": insn.size,
                "insn_id": insn.id,
                "text": f"{insn.insn_name()} {insn.op_str}",
            }
