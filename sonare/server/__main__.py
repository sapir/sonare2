import os
import cherrypy
from sonare.backend import Backend
from sonare.backend.elf_loader import load_elf


def range_to_dict(r):
    d = {
        "name": r.name,
        "start": r.start,
        "size": r.size,
    }
    d.update(r.attrs)
    return d


class Root(object):
    pass


class Sonare2WebServer(object):
    def __init__(self):
        self.backend = Backend()
        load_elf(self.backend, "test.so")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def names(self):
        return list(map(range_to_dict, self.backend.names.iter_by_name()))


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
