import re
import capstone
from capstone.arm_const import *
from enum import Enum
from .base import BaseArch, TokenWriter


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

    @staticmethod
    def _get_reg_name(insn, reg):
        if reg == 0:
            return None
        else:
            return insn.reg_name(reg)

    @staticmethod
    def _operand_to_dict(insn, op):
        d = {}

        # TODO: string type
        d["type"] = op.type

        if op.type == ARM_OP_REG:
            d["reg"] = ArmArch._get_reg_name(insn, op.reg)

        if op.type in (ARM_OP_IMM, ARM_OP_PIMM, ARM_OP_CIMM):
            d["imm"] = op.imm

        if op.type == ARM_OP_FP:
            d["fp"] = op.fp

        if op.type == ARM_OP_SYSREG:
            # TODO: merge with reg
            d["sysreg"] = op.reg

        if op.type == ARM_OP_SETEND:
            # TODO: string type
            d["setend"] = op.setend  # ARM_SETEND_BE, ARM_SETEND_LE

        if op.type == ARM_OP_MEM:
            d["base"] = ArmArch._get_reg_name(insn, op.mem.base)
            d["index"] = ArmArch._get_reg_name(insn, op.mem.index)
            d["scale"] = op.mem.scale
            d["disp"] = op.mem.disp

        if op.shift.type != ARM_SFT_INVALID and op.shift.value:
            d["shift"] = {
                "type": op.shift.type,
                "value": op.shift.value,
            }

        if op.vector_index != -1:
            d["vector_index"] = op.vector_index

        d["subtracted"] = op.subtracted

        return d

    def _analyze_insn_tokens(self, insn, cc_str, operands, simple_text):
        tw = TokenWriter()

        tw.add("mnemonic", insn.insn_name())

        if cc_str:
            tw.add("mnemonic_suffix", cc_str)

        tw.write(" ")

        # parse op_str
        op_idx = 0
        for m in re.finditer(
                # '{' signifies a register list except for printCoprocOptionImm
                r"([ \t,]+)|\[[^]]*\]|\{[0-9][^}]*\}|[^,]+", insn.op_str):

            if m.group(1):
                tw.write(m.group(1))
            else:
                tw.add("operand", m.group(), index=op_idx)
                op_idx += 1

        assert len([t for t in tw.tokens
                    if t["type"] == "operand"]) == len(operands), tw.tokens
        assert ''.join(t["string"] for t in tw.tokens) == simple_text

        return tw.tokens

    def analyze_opcodes(self, start, end, mode=None):
        cs_mode = self._get_capstone_mode(mode)

        for insn in self._disassemble(self.cs, cs_mode, start, end):
            cc = ArmArch.ConditionCode(insn.cc)
            cc_str = "" if cc == ArmArch.ConditionCode.al else cc.name

            flow = self._analyze_flow(insn, cc)

            operands = [
                self._operand_to_dict(insn, op)
                for op in insn.operands
            ]

            simple_text = f"{insn.insn_name()}{cc_str} {insn.op_str}"

            tokens = self._analyze_insn_tokens(
                insn, cc_str, operands, simple_text)

            yield {
                "address": insn.address,
                "size": insn.size,
                "insn_id": insn.id,
                "insn_name": insn.insn_name() + cc_str,
                "operands": operands,
                "tokens": tokens,
                "flow": flow,
                "text": simple_text,
            }
