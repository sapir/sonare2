import os
import cherrypy
from sonare.backend import Backend
from sonare.backend.loaders import load_elf
from sonare.backend.analysis import analyze_func


def range_to_dict(r):
    d = {
        "name": r.name,
        "start": r.start,
        "size": r.size,
    }
    d.update(r.attrs)
    return d


def ranges_to_list(rs):
    return list(map(range_to_dict, rs))


class Root(object):
    pass


class Sonare2WebServer(object):
    def __init__(self):
        self.backend = Backend(userdb_filename="server.userdb")
        load_elf(self.backend, "test.so")

    def get_reffed_addrs(self, from_addrs):
        asm_lines = self.backend.asm_lines.get_at_many(from_addrs)

        result = set()

        for line in asm_lines:
            for op in line.attrs.get("operands", []):
                if "ref" in op:
                    try:
                        value = op["value"]
                    except KeyError:
                        value = op["imm"]

                    result.add(value)

        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def names(self):
        return ranges_to_list(self.backend.names.iter_by_name())

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def func(self, name):
        # TODO: clear up where names should really be,
        # names/functions/asm_lines, including user inputs.

        # get name by both user db and main db
        name_obj = self.backend.user_lines.get_by_name(name)
        if name_obj is None:
            name_obj = self.backend.names.get_by_name(name)
            if name_obj is None:
                raise Exception(f"func {name!r} not found")

        addr = name_obj.start
        func = self.backend.functions.get_at(addr)
        if func is None:
            raise Exception(
                f"{name!r}={addr:#x} but func @ {addr:#x} not found")

        analyze_func(self.backend, func)

        func_end = func.start + func.size

        d = range_to_dict(func)

        extra_tables = ["names", "asm_lines", "user_lines"]

        for table_name in extra_tables:
            table = getattr(self.backend, table_name)
            d[table_name] = ranges_to_list(
                table.iter_where_overlaps(func.start, func_end))

        # TODO: we maybe need to get addrs reffed by the first bunch of reffed
        # addrs, to display reffed asm_lines correctly
        reffed_addrs = self.get_reffed_addrs(
            line["start"] for line in d["asm_lines"])

        for table_name in extra_tables:
            table = getattr(self.backend, table_name)
            d[table_name] += ranges_to_list(
                table.get_at_many(reffed_addrs))

        return d

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def set_line_name(self):
        j = cherrypy.request.json
        with self.backend.userdb:
            self.backend.user_lines.upsert(j["addr"], name=j["name"])

        return {"ok": True}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def set_line_comment(self):
        j = cherrypy.request.json
        with self.backend.userdb:
            self.backend.user_lines.upsert(j["addr"], comment=j["comment"])

        return {"ok": True}


if __name__ == '__main__':
    static_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..", "webapp", "build"))

    cherrypy.tree.mount(
        Root(),
        "/",
        config={
            "/": {
                "tools.staticdir.on": True,
                "tools.staticdir.dir": static_path,
                "tools.staticdir.index": "index.html",
            }
        })

    cherrypy.quickstart(Sonare2WebServer(), "/api")
