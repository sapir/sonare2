import capstone
from enum import Enum
from .base import BaseArch


class ArmArch(BaseArch):
    ConditionCode = Enum(
        "ConditionCode",
        "invalid eq ne hs lo mi pl vs vc hi ls ge lt gt le al",
        start=0)

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
            cc = ArmArch.ConditionCode(insn.cc)
            cc_str = "" if cc == ArmArch.ConditionCode.al else cc.name

            yield {
                "address": insn.address,
                "size": insn.size,
                "insn_id": insn.id,
                "text": f"{insn.insn_name()}{cc_str} {insn.op_str}",
            }
