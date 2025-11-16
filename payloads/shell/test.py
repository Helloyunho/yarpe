global dump_dict, renpy

def foo():
    l = { "test": True, "name": renpy.config.name }
    dump_dict(l)
