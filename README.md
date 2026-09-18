import sys
import struct
import pefile

def bypass(inp, out):
    pe = pefile.PE(inp)
    oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    sec = next(s for s in pe.sections if s.IMAGE_SCN_MEM_EXECUTE)

    raw = sec.get_data()
    offset = sec.PointerToRawData + len(raw.rstrip(b'\x00'))
    rva = sec.VirtualAddress + (offset - sec.PointerToRawData)

    rel = oep - (rva + 5)
    payload = b"\xE9" + struct.pack("<i", rel)

    pe.set_bytes_at_offset(offset, payload)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = rva
    pe.write(out)
    pe.close()

if name == "main":
    bypass(sys.argv[1], sys.argv[2])
