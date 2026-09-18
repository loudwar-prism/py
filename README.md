rtf_parser = rtfobj.RtfObjParser(file_path)
            rtf_parser.parse()
            
            if rtf_parser.objects:
                for idx, obj in enumerate(rtf_parser.objects):
                    if obj.is_ole and obj.ole_data:
                        try:
                            ole = olefile.OleFileIO(obj.ole_data)
                            for stream_path in ole.listdir():
                                stream_data = ole.openstream(stream_path).read()
                                full_stream_name = f"RTF_Obj_{idx}/" + "/".join(stream_path)
                                s_sha256 = hashlib.sha256(stream_data).digest().hex()
                                print(f"  Stream (RTF): {full_stream_name} | SHA-256: {s_sha256}")
                            ole.close()
                        except Exception:
                            s_sha256 = hashlib.sha256(obj.ole_data).digest().hex()
                            print(f"  Embedded Object {idx} | SHA-256: {s_sha256}")
            else:
                print("  [!] Файл не содержит OLE структур или встроенных объектов")

    except Exception as e:
        print(f"Ошибка при анализе файла {file_path}: {e}")
