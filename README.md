import os
import hashlib
from datetime import datetime, timezone
import pefile
import magic
import ssdeep
from oletools.olevba import VBA_Parser
from exif import Image

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except Exception:
        return None

    print(f"\n=== PE: {os.path.basename(file_path)} ===")
    ts = pe.FILE_HEADER.TimeDateStamp
    print(f"TimeDateStamp: {datetime.fromtimestamp(ts, tz=timezone.utc)}")

    print("PE Resources:")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for r_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for r_id in r_type.directory.entries:
                for r_lang in r_id.directory.entries:
                    offset = r_lang.data.struct.OffsetToData
                    size = r_lang.data.struct.Size
                    res_bytes = pe.get_data(offset, size)
                    m_type = magic.from_buffer(res_bytes)
                    print(f"  Offset: 0x{offset:X} | Size: {size} B | Magic: {m_type}")
    else:
        print("  No resources")

    sec_hashes = {}
    print("Sections ssdeep:")
    for sec in pe.sections:
        s_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
        s_hash = ssdeep.hash(sec.get_data())
        sec_hashes[s_name] = s_hash
        print(f"  {s_name:<8}: {s_hash}")
        
    return sec_hashes

def analyze_ole(file_path):
    try:
        vba = VBA_Parser(file_path)
        if not vba.is_ole():
            return
        
        print(f"\n=== OLE: {os.path.basename(file_path)} ===")
        for _, stream_path, ole_data in vba.extract_streams():
            if not ole_data:
                continue
            
            s_sha256 = hashlib.sha256(ole_data).hexdigest()
            print(f"Stream: {stream_path} | SHA-256: {s_sha256}")

            m_type = magic.from_buffer(ole_data)
            if "image" in m_type.lower():
                try:
                    img = Image(ole_data)
                    if img.has_exif:
                        print("  EXIF Metadata:")
                        for attr in img.list_all():
                            print(f"    {attr}: {getattr(img, attr)}")
                except Exception:
                    pass
    except Exception:
        pass

if name == "main":
    all_pe_hashes = {}
    
    for fname in os.listdir('.'):
        if not os.path.isfile(fname) or fname.endswith('.py'):
            continue
            
        hashes = analyze_pe(fname)
        if hashes:
            all_pe_hashes[fname] = hashes
            
        analyze_ole(fname)

    files = list(all_pe_hashes.keys())
    if len(files) > 1:
        print("\n=== ssdeep Comparison ===")
        for i in range(len(files)):
            for j in range(i + 1, len(files)):
                f1, f2 = files[i], files[j]
                print(f"\n{f1} <-> {f2}:")
                for s1, h1 in all_pe_hashes[f1].items():
                    if s1 in all_pe_hashes[f2]:
                        h2 = all_pe_hashes[f2][s1]
                        score = ssdeep.compare(h1, h2)
                        print(f"  {s1}: {score}% similarity")
