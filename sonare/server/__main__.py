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

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def names(self):
        return ranges_to_list(self.backend.names.iter_by_name())

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def func(self, name):
        func = self.backend.functions.get_by_name(name)
        if func is None:
            raise Exception(f"func {name!r} not found")

        analyze_func(self.backend, func)

        func_end = func.start + func.size

        d = range_to_dict(func)

        d["asm_lines"] = ranges_to_list(
            self.backend.asm_lines.iter_where_overlaps(
                func.start, func_end))

        d["user_lines"] = ranges_to_list(
            self.backend.user_lines.iter_where_overlaps(
                func.start, func_end))

        return d


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
