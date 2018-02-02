class BaseArch:
    def __init__(self, backend):
        self.backend = backend

    def hook_load_symbol(self, sym):
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
