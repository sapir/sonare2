import re
import itertools
from binascii import unhexlify
from subprocess import check_output
import sonare
from .base import BaseArch, TokenWriter


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
            # TODO: any tailcall to a function, not just jmp 0
            if line["text"] in ["ret", "reti", "jmp 0", "ijmp", "eijmp"]
        ]

        # let last function end at end of file = last_line_end
        last_line_end = raw_asm_lines[-1]["end"]
        for func_start, next_func_start in zip(
                func_starts, func_starts[1:] + [last_line_end]):

            func_name = f"func_{func_start:x}"
            name_obj = sonare.backend.Range(
                func_start, next_func_start, name=func_name)
            self.backend.names.add_obj(name_obj)

            func_obj = name_obj.copy_new()
            self.backend.functions.add_obj(func_obj)

    def _operand_to_dict(self, asm_line, op_str):
        if op_str.startswith("."):
            # ".+decimal" or ".-decimal"
            disp = int(op_str[1:])
            tgt = asm_line.end + disp
            return {
                "type": "rel",
                "disp": disp,
                "value": tgt,
            }

        try:
            value = int(op_str, 0)
        except ValueError:
            pass
        else:
            return {
                "type": "imm",
                "imm": value,
            }

        if op_str.startswith("r"):
            return {
                "type": "reg",
                "reg": op_str,
            }

        m = re.match(r"^(-?)([XYZ])(\+?)(\d*)$", op_str)
        if m:
            disp_str = m.group(4)

            if disp_str:
                disp = int(disp_str)
                assert not m.group(1)
                predec = False
                postinc = False
            else:
                predec = bool(m.group(1))
                postinc = bool(m.group(3))
                disp = 0

            return {
                "type": "mem",
                "base": m.group(2),
                "disp": disp,
                "predec": predec,
                "postinc": postinc,
            }

        raise NotImplementedError(
            f"operand {op_str!r} in {asm_line.attrs['text']!r}"
            f" @ {asm_line.start:#x} not supported")

    def _analyze_operand_types(self, asm_line, insn_name, operands):
        # jumps, calls and branches, but not indirect ones
        if (("jmp" in insn_name and "ijmp" not in insn_name) or
                ("call" in insn_name and "icall" not in insn_name) or
                insn_name.startswith("br")):

            operands[0].update(
                dtype="ref",
                ref={
                    "dtype": "func" if "call" in insn_name else "code",
                    # unknown size
                    "size": None,
                }
            )

    def _analyze_insn_tokens(self, asm_line, insn_name, operands):
        tw = TokenWriter()

        tw.add("mnemonic", insn_name)

        if operands:
            tw.write(" ")

        for op_idx, operand in enumerate(operands):
            if op_idx > 0:
                tw.write(", ")

            part_idxes = itertools.count()

            def write_op_part(part_type, string):
                tw.add(
                    "operand",
                    string,
                    index=op_idx,
                    part_idx=next(part_idxes),
                    part_type=part_type)

            if operand["type"] == "rel":
                write_op_part("base", ".")
                write_op_part("disp", format(operand["disp"], "+#x"))

            elif operand["type"] == "imm":
                write_op_part("main", format(operand["imm"], "#x"))

            elif operand["type"] == "reg":
                write_op_part("main", operand["reg"])

            elif operand["type"] == "mem":
                if operand["predec"]:
                    write_op_part("syntax", "-")

                write_op_part("base", operand["base"])

                if operand["postinc"]:
                    write_op_part("syntax", "+")

                if operand["disp"]:
                    write_op_part("disp", format(operand["disp"], "+#x"))

            else:
                raise NotImplementedError(f"unsupported operand {operand!r}")

        return tw.tokens

    def _analyze_flow(self, asm_line, insn_name, operands):
        if insn_name in ["ijmp", "eijmp", "ret", "reti"]:
            # don't know next instruction address, it's an indirect jump
            return []

        flow = []

        next_addr = asm_line.end

        if insn_name in ["rjmp", "rcall"] or insn_name.startswith("br"):
            assert operands[0]["type"] == "rel"
            flow.append(next_addr + operands[0]["disp"])

        elif insn_name in ["jmp"]:
            flow.append(operands[0]["imm"])

        # branch flow for "skip if" instructions, i.e. cpse, sbrc, sbrs, sbic,
        # sbis
        elif insn_name in ["cpse", "sbrc", "sbrs", "sbic", "sbis"]:
            next_asm_line = self.backend.asm_lines.get_at(asm_line.end)
            # TODO: warning if next_asm_line is missing?
            # TODO: this should generate a dependency on the next line
            if next_asm_line:
                flow.append(next_asm_line.end)

        # don't know target address for icall and eicall, so treat it as a
        # regular instruction, i.e. flow continues to next instruction

        if not insn_name.endswith("jmp"):
            flow.append(next_addr)

        return flow

    def _analyze_opcodes(self, start, end, mode=None):
        for asm_line in self.backend.asm_lines.iter_where_overlaps(start, end):
            text = asm_line.attrs["text"]

            if " " in text:
                insn_name, op_str = text.split(None, 1)
                op_strs = [x.strip() for x in op_str.split(",")]
            else:
                insn_name = text
                op_strs = []

            operands = [self._operand_to_dict(asm_line, op) for op in op_strs]

            self._analyze_operand_types(asm_line, insn_name, operands)

            tokens = self._analyze_insn_tokens(asm_line, insn_name, operands)

            flow = self._analyze_flow(asm_line, insn_name, operands)

            yield {
                # these 2 are required even though asm_line exists already
                "address": asm_line.start,
                "size": asm_line.size,

                "insn_name": insn_name,
                "operands": operands,
                "tokens": tokens,
                "flow": flow,
                "text": text,
            }

    def are_reg_pair(self, op1, op2):
        if op1["type"] == "reg" and op2["type"] == "reg":
            n1 = int(op1["reg"][1:])
            n2 = int(op2["reg"][1:])
            if n2 == n1 + 1:
                return True

        return False

    def analyze_opcodes(self, *args, **kwargs):
        ret = list(self._analyze_opcodes(*args, **kwargs))

        i = 0
        while i < len(ret) - 1:
            line1 = ret[i]
            line2 = ret[i + 1]
            if line1.get("elided"):
                i += 1
                continue

            insn_names = (line1["insn_name"], line2["insn_name"])

            if (insn_names in [("subi", "sbci"), ("ldi", "ldi")]):
                reg1, imm1 = line1["operands"]
                reg2, imm2 = line2["operands"]
                if self.are_reg_pair(reg1, reg2):
                    word = (imm2["imm"] << 8) | imm1["imm"]
                    if word >= 0x8000:
                        word -= (1 << 16)

                    line1["tokens"][0]["string"] = insn_names[0] + "w"
                    line1["tokens"][-1]["string"] = format(word, "#x")
                    line2["tokens"] = [{"type": "mnemonic", "string": "---"}]
                    line2["elided"] = True

            elif (insn_names in [("ld", "ldd"),
                                 ("ldd", "ldd"),
                                 ("st", "std"),
                                 ("std", "std")]):

                if insn_names[0].startswith("ld"):
                    reg1, tgt1 = line1["operands"]
                    reg2, tgt2 = line2["operands"]
                else:
                    tgt1, reg1 = line1["operands"]
                    tgt2, reg2 = line2["operands"]

                if (self.are_reg_pair(reg1, reg2) and
                        tgt2["base"] == tgt1["base"] and
                        tgt2["disp"] == tgt1["disp"] + 1 and
                        not tgt1["predec"] and not tgt1["postinc"] and
                        not tgt2["predec"] and not tgt2["postinc"]):

                    line1["tokens"][0]["string"] = insn_names[0] + "w"
                    line2["tokens"] = [{"type": "mnemonic", "string": "---"}]
                    line2["elided"] = True

            i += 1

        return ret
