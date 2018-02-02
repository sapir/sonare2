import capstone
from capstone.arm_const import *
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

    def _analyze_flow(self, insn, cc):
        if insn.id in [ARM_INS_B]:
            # flow continues to operand
            is_branch = True
            branch_target = insn.operands[0].imm
        elif insn.id in [ARM_INS_BX, ARM_INS_BXJ]:
            # flow continues to register (a tailcall or return)
            is_branch = True
            branch_target = None  # unknown
        else:
            is_branch = False

        is_cond = (cc != ArmArch.ConditionCode.al)

        flow = []
        if is_branch and branch_target:
            flow.append(branch_target)

        if not is_branch or is_cond:
            next_addr = insn.address + insn.size
            flow.append(next_addr)

        return flow

    def analyze_opcodes(self, start, end, mode=None):
        cs_mode = self._get_capstone_mode(mode)

        for insn in self._disassemble(self.cs, cs_mode, start, end):
            cc = ArmArch.ConditionCode(insn.cc)
            cc_str = "" if cc == ArmArch.ConditionCode.al else cc.name

            flow = self._analyze_flow(insn, cc)

            yield {
                "address": insn.address,
                "size": insn.size,
                "insn_id": insn.id,
                "flow": flow,
                "text": f"{insn.insn_name()}{cc_str} {insn.op_str}",
            }
