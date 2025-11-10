import struct
from utils.ref import get_ref_addr, refbytes
from utils.etc import alloc, addrof, bytes
from utils.unsafe import fakeobj
from utils.pack import p64a
from constants import nogc


class Structure(object):
    def __init__(self, sizes):
        self._sizes = sizes
        self.sizes = {}
        self.calculate()

    def calculate(self):
        self.size = 0
        self.offsets = {}
        for field_name, field_size in self._sizes:
            self.sizes[field_name] = field_size
            self.offsets[field_name] = self.size
            self.size += field_size

    def create(self, defaults=None):
        buf = StructureInstance(self, defaults)
        return buf

    def from_bytes(self, data):
        if len(data) != self.size:
            raise Exception("Data size does not match structure size")
        instance = StructureInstance(self)
        instance.buf[:] = data
        return instance

    def from_bytearray(self, data):
        if len(data) != self.size:
            raise Exception("Data size does not match structure size")
        instance = StructureInstance(self)
        instance.buf = data
        return instance

    def from_address(self, addr):
        fake_bytearray = bytes(p64a(1, addrof(bytearray), self.size, 0, 0, addr, 0))
        nogc.append(fake_bytearray)

        data = fakeobj(refbytes(fake_bytearray))
        return self.from_bytearray(data)


class StructureInstance(object):
    def __init__(self, structure, defaults=None):
        self.structure = structure
        self.buf = alloc(self.structure.size)
        self.size = self.structure.size
        if defaults:
            for key, value in defaults.items():
                self.set_field(key, value)

    @property
    def addr(self):
        return get_ref_addr(self.buf)

    def reset(self):
        self.buf[:] = b"\0" * len(self.buf)

    def set_field_raw(self, field_name, data):
        offset = self.structure.offsets[field_name]
        data_len = len(data)
        if data_len > self.structure.sizes[field_name]:
            raise Exception("Data size exceeds field size")
        self.buf[offset : offset + data_len] = data

    def set_field(self, field_name, value):
        offset = self.structure.offsets[field_name]
        field_size = self.structure.sizes[field_name]
        if field_size in [1, 2, 4, 8]:
            converted_val = get_ref_addr(value)
            if field_size == 1:
                value = struct.pack("<B", converted_val)
            elif field_size == 2:
                value = struct.pack("<H", converted_val)
            elif field_size == 4:
                value = struct.pack("<I", converted_val)
            elif field_size == 8:
                value = struct.pack("<Q", converted_val)

            self.buf[offset : offset + field_size] = value
        else:
            self.set_field_raw(field_name, value)

    def get_field_raw(self, field_name):
        offset = self.structure.offsets[field_name]
        size = self.structure.sizes[field_name]
        return self.buf[offset : offset + size]

    def get_field(self, field_name):
        offset = self.structure.offsets[field_name]
        size = self.structure.sizes[field_name]
        data = self.buf[offset : offset + size]
        if size in [1, 2, 4, 8]:
            if size == 1:
                return struct.unpack("<B", data)[0]
            elif size == 2:
                return struct.unpack("<H", data)[0]
            elif size == 4:
                return struct.unpack("<I", data)[0]
            elif size == 8:
                return struct.unpack("<Q", data)[0]
        else:
            return data

    def __setitem__(self, key, value):
        if key in self.structure.offsets:
            self.set_field(key, value)
        else:
            raise KeyError("No such field: %s" % key)

    def __getitem__(self, key):
        if key in self.structure.offsets:
            return self.get_field(key)
        else:
            raise KeyError("No such field: %s" % key)

    def __setattr__(self, name, value):
        if name in ("structure", "buf", "size"):
            object.__setattr__(self, name, value)
        elif name in self.structure.offsets:
            self.set_field(name, value)
        else:
            raise AttributeError("No such field: %s" % name)

    def __getattr__(self, name):
        if name in ("structure", "buf", "size"):
            return object.__getattribute__(self, name)
        elif name in self.structure.offsets:
            return self.get_field(name)
        else:
            raise AttributeError("No such field: %s" % name)
