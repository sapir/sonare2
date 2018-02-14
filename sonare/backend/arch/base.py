class TokenWriter(object):
    def __init__(self):
        self.tokens = []

    def add(self, type_, string, **attrs):
        # merge syntax tokens
        if (type_ == "syntax" and not attrs and
                self.tokens and self.tokens[-1]["type"] == "syntax"):

            self.tokens[-1]["string"] += string

        else:
            t = {"type": type_, "string": string}
            t.update(attrs)
            self.tokens.append(t)

    def write(self, string):
        self.add("syntax", string)


class BaseArch:
    def __init__(self, backend):
        self.backend = backend

    def hook_load_symbol(self, sym):
        pass

    def hook_post_load_file(self):
        pass

    def _disassemble(self, cs_obj, cs_mode, start, end):
        """
        helper method to set up a disassembly iterator with an existing
        capstone object
        """

        cs_obj.mode = cs_mode

        insns_bytes = self.backend.buf_mgr.get_bytes(start, end - start)

        return self.cs.disasm(insns_bytes, start)

    def analyze_opcodes(self, start, end, mode=None):
        return
        yield
