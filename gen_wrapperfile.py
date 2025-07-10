import ctypes
import os
import shutil
import sys
from ctypes import wintypes
from textwrap import dedent


# Constants
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_DIRECTORY_ENTRY_EXPORT = 0


class Export:
    """Represents a DLL export function"""
    def __init__(self, name, ordinal):
        self.name = name
        self.ordinal = ordinal


# PE File Structures
class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", wintypes.WORD),
        ("e_cblp", wintypes.WORD),
        ("e_cp", wintypes.WORD),
        ("e_crlc", wintypes.WORD),
        ("e_cparhdr", wintypes.WORD),
        ("e_minalloc", wintypes.WORD),
        ("e_maxalloc", wintypes.WORD),
        ("e_ss", wintypes.WORD),
        ("e_sp", wintypes.WORD),
        ("e_csum", wintypes.WORD),
        ("e_ip", wintypes.WORD),
        ("e_cs", wintypes.WORD),
        ("e_lfarlc", wintypes.WORD),
        ("e_ovno", wintypes.WORD),
        ("e_res", wintypes.WORD * 4),
        ("e_oemid", wintypes.WORD),
        ("e_oeminfo", wintypes.WORD),
        ("e_res2", wintypes.WORD * 10),
        ("e_lfanew", wintypes.DWORD),
    ]


class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine", wintypes.WORD),
        ("NumberOfSections", wintypes.WORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("PointerToSymbolTable", wintypes.DWORD),
        ("NumberOfSymbols", wintypes.DWORD),
        ("SizeOfOptionalHeader", wintypes.WORD),
        ("Characteristics", wintypes.WORD),
    ]


class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", wintypes.DWORD),
        ("Size", wintypes.DWORD),
    ]


class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", wintypes.BYTE),
        ("MinorLinkerVersion", wintypes.BYTE),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("ImageBase", ctypes.c_uint64),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", ctypes.c_uint64),
        ("SizeOfStackCommit", ctypes.c_uint64),
        ("SizeOfHeapReserve", ctypes.c_uint64),
        ("SizeOfHeapCommit", ctypes.c_uint64),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16),
    ]


class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]


class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("Characteristics", wintypes.DWORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("MajorVersion", wintypes.WORD),
        ("MinorVersion", wintypes.WORD),
        ("Name", wintypes.DWORD),
        ("Base", wintypes.DWORD),
        ("NumberOfFunctions", wintypes.DWORD),
        ("NumberOfNames", wintypes.DWORD),
        ("AddressOfFunctions", wintypes.DWORD),
        ("AddressOfNames", wintypes.DWORD),
        ("AddressOfNameOrdinals", wintypes.DWORD),
    ]


class PEParser:
    """PE file parser for extracting export information"""
    
    def __init__(self, dll_path):
        self.dll_path = dll_path
        
    def rva_to_file_offset(self, rva, sections):
        """Convert RVA to file offset"""
        for section in sections:
            if (rva >= section.VirtualAddress and 
                rva < section.VirtualAddress + section.SizeOfRawData):
                return rva - section.VirtualAddress + section.PointerToRawData
        return rva
    
    def read_sections(self, file, num_sections):
        """Read section headers from PE file"""
        sections = []
        for _ in range(num_sections):
            section_data = file.read(40)  # IMAGE_SECTION_HEADER size
            section = type('Section', (), {
                'VirtualAddress': int.from_bytes(section_data[12:16], 'little'),
                'SizeOfRawData': int.from_bytes(section_data[16:20], 'little'),
                'PointerToRawData': int.from_bytes(section_data[20:24], 'little')
            })()
            sections.append(section)
        return sections
    
    def read_string_at_rva(self, file, rva, sections):
        """Read null-terminated string at given RVA"""
        offset = self.rva_to_file_offset(rva, sections)
        file.seek(offset)
        name_bytes = b''
        while True:
            byte = file.read(1)
            if byte == b'\x00':
                break
            name_bytes += byte
        return name_bytes.decode('ascii', errors='ignore')
    
    def extract_exports(self):
        """Extract export functions from DLL"""
        if not os.path.exists(self.dll_path):
            print(f"Error: File not found: {self.dll_path}")
            return []
        
        try:
            with open(self.dll_path, 'rb') as f:
                # Read DOS header
                dos_header = IMAGE_DOS_HEADER()
                f.readinto(dos_header)
                
                if dos_header.e_magic != IMAGE_DOS_SIGNATURE:
                    print("Error: Invalid PE file")
                    return []
                
                # Read NT headers
                f.seek(dos_header.e_lfanew)
                nt_headers = IMAGE_NT_HEADERS64()
                f.readinto(nt_headers)
                
                if nt_headers.Signature != IMAGE_NT_SIGNATURE:
                    print("Error: Invalid NT header")
                    return []
                
                # Get export directory
                export_dir_entry = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                if export_dir_entry.VirtualAddress == 0:
                    print("Error: No export table found")
                    return []
                
                # Read section headers
                sections = self.read_sections(f, nt_headers.FileHeader.NumberOfSections)
                
                # Read export directory
                export_dir_offset = self.rva_to_file_offset(export_dir_entry.VirtualAddress, sections)
                f.seek(export_dir_offset)
                export_dir = IMAGE_EXPORT_DIRECTORY()
                f.readinto(export_dir)
                
                # Extract exports
                return self._extract_export_functions(f, export_dir, sections)
                
        except Exception as e:
            print(f"Error processing file: {e}")
            return []
    
    def _extract_export_functions(self, file, export_dir, sections):
        """Extract individual export functions"""
        names_offset = self.rva_to_file_offset(export_dir.AddressOfNames, sections)
        ordinals_offset = self.rva_to_file_offset(export_dir.AddressOfNameOrdinals, sections)
        
        exports = []
        
        for i in range(export_dir.NumberOfNames):
            # Read name RVA
            file.seek(names_offset + i * 4)
            name_rva = int.from_bytes(file.read(4), 'little')
            
            # Read ordinal
            file.seek(ordinals_offset + i * 2)
            ordinal = int.from_bytes(file.read(2), 'little') + export_dir.Base
            
            # Read function name
            function_name = self.read_string_at_rva(file, name_rva, sections)
            exports.append(Export(function_name, ordinal))
        
        # Sort by ordinal
        exports.sort(key=lambda x: x.ordinal)
        return exports


class WrapperGenerator:
    """Generates wrapper files for DLL hijacking"""
    
    def __init__(self, dll_path, exports):
        self.dll_path = dll_path
        self.dll_name = os.path.splitext(os.path.basename(dll_path))[0]
        self.exports = exports
        self.output_dir = "wrapper"
    
    def generate_all(self):
        """Generate all wrapper files"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        self._generate_def_file()
        self._generate_cpp_file()
        self._generate_asm_file()
        self._copy_original_dll()
        
        print(f"Successfully generated {len(self.exports)} export functions")
        print(f"Output files: {self.dll_name}.def, {self.dll_name}_functions.cpp, {self.dll_name}_wrapper.asm")
    
    def _generate_def_file(self):
        """Generate .def file"""
        with open(f"{self.output_dir}/{self.dll_name}.def", "w") as f:
            f.write(f"LIBRARY {self.dll_name.upper()}\n")
            f.write("EXPORTS\n")
            for export in self.exports:
                f.write(f"\t{export.name} @{export.ordinal}\n")
    
    def _generate_cpp_file(self):
        """Generate C++ functions file"""
        with open(f"{self.output_dir}/{self.dll_name}_functions.cpp", "w") as f:
            f.write("#include <Windows.h>\n")
            f.write("#include <string>\n")
            f.write("#include \"../main.h\"\n\n")
            
            f.write("extern \"C\" {\n")
            for export in self.exports:
                f.write(f"\tFARPROC orig_{export.name};\n")
            f.write("}\n\n")
            
            f.write(self._get_functions_class_template())
    
    def _get_functions_class_template(self):
        """Get the functions class template"""
        return dedent(f"""
            class functions {{
            public:
                functions() {{
                    dllentry entry;
                    
                    if (GetFileAttributesA("{self.dll_name}_orig.dll") == INVALID_FILE_ATTRIBUTES) {{
                        char sysDir[MAX_PATH];
                        GetSystemDirectoryA(sysDir, MAX_PATH);
                        std::string src = std::string(sysDir) + "\\\\{self.dll_name}.dll";
                        if (!CopyFileA(src.c_str(), "{self.dll_name}_orig.dll", FALSE)) {{
                            DWORD err = GetLastError();
                        }}
                    }}
                    
                    const auto module = LoadLibrary("{self.dll_name}_orig.dll");
                    {self._get_proc_address_calls()}
                }}
            }} functions;
            """)
    
    def _get_proc_address_calls(self):
        """Generate GetProcAddress calls for all exports"""
        calls = []
        for export in self.exports:
            calls.append(f'\t\torig_{export.name} = GetProcAddress(module, "{export.name}");')
        return '\n'.join(calls)
    
    def _generate_asm_file(self):
        """Generate assembly wrapper file"""
        with open(f"{self.output_dir}/{self.dll_name}_wrapper.asm", "w") as f:
            # External declarations
            for export in self.exports:
                f.write(f"extern orig_{export.name}:QWORD\n")
                f.write(f"{export.name} proto\n\n")
            
            f.write("\n.code\n")
            
            # Function implementations
            for export in self.exports:
                f.write(dedent(f"""
                    {export.name} proc
                            jmp     [orig_{export.name}]
                    {export.name} endp
                    """))
            
            f.write("end")
    
    def _copy_original_dll(self):
        """Copy original DLL to project root"""
        orig_dll_name = f"{self.dll_name}_orig.dll"
        try:
            shutil.copy2(self.dll_path, orig_dll_name)
            print(f"Original DLL copied as: {orig_dll_name}")
        except Exception as e:
            print(f"Error copying original DLL: {e}")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python wrapper_gen.py <dll_path>")
        return
    
    dll_path = sys.argv[1]
    
    # Extract exports from DLL
    parser = PEParser(dll_path)
    exports = parser.extract_exports()
    
    if not exports:
        print("Failed to extract export information")
        return
    
    # Generate wrapper files
    generator = WrapperGenerator(dll_path, exports)
    generator.generate_all()


if __name__ == "__main__":
    main()