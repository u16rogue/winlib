#pragma once

#include <cstddef>
#include <metapp/metapp.hh>

namespace winlib {

struct WinUnicodeString {
  mpp::u16 length;
  mpp::u16 maxlen;
  wchar_t * buff;
};

struct __attribute__((packed)) LDRDataTableEntry64 {
  LDRDataTableEntry64 * next;
  mpp::u8         _pad0[40];
  mpp::u8 *       base_address;
  mpp::u8         _pad1[8];
  mpp::u64        size;
  const WinUnicodeString name_full;
  const WinUnicodeString name;
};
static_assert(offsetof(LDRDataTableEntry64, next)         == 0x00);
static_assert(offsetof(LDRDataTableEntry64, base_address) == 0x30);
static_assert(offsetof(LDRDataTableEntry64, size)         == 0x40);
static_assert(offsetof(LDRDataTableEntry64, name_full)    == 0x48);

struct __attribute__((packed)) PEBLDRData64 {
  mpp::u8 _pad0[16];
  LDRDataTableEntry64 * entry_order_load;
  mpp::u8 _pad1[8];
  LDRDataTableEntry64 * entry_order_mem;
};
static_assert(offsetof(PEBLDRData64, entry_order_load) == 0x10);
static_assert(offsetof(PEBLDRData64, entry_order_mem)  == 0x20);

struct __attribute__((packed)) PEB64 {
  mpp::u8        _pad0[2];
  bool           being_debugged;
  mpp::u8        _pad1[21];
  PEBLDRData64 * ldr_data;
  mpp::u8        _pad2[156];
  mpp::u32       nt_global_flag;
};
static_assert(offsetof(PEB64, being_debugged) == 0x02);
static_assert(offsetof(PEB64, ldr_data)       == 0x18);

#undef IMAGE_FILE_MACHINE_IA64 
#undef IMAGE_FILE_MACHINE_AMD64
#undef IMAGE_FILE_MACHINE_I386 
constexpr mpp::u16 IMAGE_FILE_MACHINE_IA64  = 0x0200;
constexpr mpp::u16 IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr mpp::u16 IMAGE_FILE_MACHINE_I386  = 0x014c;

#undef IMAGE_NUMBEROF_DIRECTORY_ENTRIES
#undef IMAGE_DIRECTORY_ENTRY_EXPORT    
#undef IMAGE_DIRECTORY_ENTRY_IMPORT    
#undef IMAGE_DIRECTORY_ENTRY_BASERELOC 
#undef IMAGE_DIRECTORY_ENTRY_TLS       
constexpr mpp::u32 IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
constexpr mpp::u32 IMAGE_DIRECTORY_ENTRY_EXPORT     = 0;
constexpr mpp::u32 IMAGE_DIRECTORY_ENTRY_IMPORT     = 1;
constexpr mpp::u32 IMAGE_DIRECTORY_ENTRY_BASERELOC  = 5;
constexpr mpp::u32 IMAGE_DIRECTORY_ENTRY_TLS        = 9;

#undef IMAGE_NT_OPTIONAL_HDR32_MAGIC
#undef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#undef IMAGE_ROM_OPTIONAL_HDR_MAGIC 
constexpr mpp::u16 IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010b;
constexpr mpp::u16 IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020b;
constexpr mpp::u16 IMAGE_ROM_OPTIONAL_HDR_MAGIC  = 0x0107;

#undef IMAGE_SCN_CNT_CODE   
#undef IMAGE_SCN_MEM_EXECUTE
constexpr mpp::u32 IMAGE_SCN_CNT_CODE    = 0x00000020;
constexpr mpp::u32 IMAGE_SCN_MEM_EXECUTE = 0x20000000;

#undef IMAGE_SIZEOF_SHORT_NAME
constexpr mpp::i32 IMAGE_SIZEOF_SHORT_NAME = 8;

struct DOSHeader {
  mpp::u16 e_magic;
  mpp::u16 e_cblp;
  mpp::u16 e_cp;
  mpp::u16 e_crlc;
  mpp::u16 e_cparhdr;
  mpp::u16 e_minalloc;
  mpp::u16 e_maxalloc;
  mpp::u16 e_ss;
  mpp::u16 e_sp;
  mpp::u16 e_csum;
  mpp::u16 e_ip;
  mpp::u16 e_cs;
  mpp::u16 e_lfarlc;
  mpp::u16 e_ovno;
  mpp::u16 e_res[4];
  mpp::u16 e_oemid;
  mpp::u16 e_oeminfo;
  mpp::u16 e_res2[10];
  mpp::u32 e_lfanew;
};

struct DataDirectory {
  mpp::u32 VirtualAddress;
  mpp::u32 Size;
};

struct NTHeaders64 {
  mpp::u32 Signature;
  // -- IMAGE_FILE_HEADER FileHeader;
  mpp::u16 Machine;
  mpp::u16 NumberOfSections;
  mpp::u32 TimeDateStamp;
  mpp::u32 PointerToSymbolTable;
  mpp::u32 NumberOfSymbols;
  mpp::u16 SizeOfOptionalHeader;
  mpp::u16 Characteristics;
  // -- IMAGE_OPTIONAL_HEADER OptionalHeader;
  mpp::u16 Magic;
  mpp::u8  MajorLinkerVersion;
  mpp::u8  MinorLinkerVersion;
  mpp::u32 SizeOfCode;
  mpp::u32 SizeOfInitializedData;
  mpp::u32 SizeOfUninitializedData;
  mpp::u32 AddressOfEntryPoint;
  mpp::u32 BaseOfCode;
  mpp::u64 ImageBase;
  mpp::u32 SectionAlignment;
  mpp::u32 FileAlignment;
  mpp::u16 MajorOperatingSystemVersion;
  mpp::u16 MinorOperatingSystemVersion;
  mpp::u16 MajorImageVersion;
  mpp::u16 MinorImageVersion;
  mpp::u16 MajorSubsystemVersion;
  mpp::u16 MinorSubsystemVersion;
  mpp::u32 Win32VersionValue;
  mpp::u32 SizeOfImage;
  mpp::u32 SizeOfHeaders;
  mpp::u32 CheckSum;
  mpp::u16 Subsystem;
  mpp::u16 DllCharacteristics;
  mpp::u64 SizeOfStackReserve;
  mpp::u64 SizeOfStackCommit;
  mpp::u64 SizeOfHeapReserve;
  mpp::u64 SizeOfHeapCommit;
  mpp::u32 LoaderFlags;
  mpp::u32 NumberOfRvaAndSizes;
  DataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct ExportDirectory {
  mpp::u32 Characteristics;
  mpp::u32 TimeDateStamp;
  mpp::u16 MajorVersion;
  mpp::u16 MinorVersion;
  mpp::u32 Name;
  mpp::u32 Base;
  mpp::u32 NumberOfFunctions;
  mpp::u32 NumberOfNames;
  mpp::u32 AddressOfFunctions;
  mpp::u32 AddressOfNames;
  mpp::u32 AddressOfNameOrdinals;
};

struct SectionHeader {
  mpp::u8  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    mpp::u32 PhysicalAddress;
    mpp::u32 VirtualSize;
  } Misc;
  mpp::u32 VirtualAddress;
  mpp::u32 SizeOfRawData;
  mpp::u32 PointerToRawData;
  mpp::u32 PointerToRelocations;
  mpp::u32 PointerToLinenumbers;
  mpp::u16 NumberOfRelocations;
  mpp::u16 NumberOfLinenumbers;
  mpp::u32 Characteristics;
}; 

struct BaseRelocation {
  mpp::u32 VirtualAddress;
  mpp::u32 SizeOfBlock;
};

struct ImportDescriptor {
  union {
    mpp::u32 Characteristics;
    mpp::u32 OriginalFirstThunk;
  };
  mpp::u32 TimeDateStamp;
  mpp::u32 ForwarderChain;
  mpp::u32 Name;
  mpp::u32 FirstThunk;
}; 

struct ImportByNameInfo {
  mpp::u16 Hint;
  char Name[1];
};

struct TLSDirectory64 {
  mpp::u64 StartAddressOfRawData;
  mpp::u64 EndAddressOfRawData;
  mpp::u64 AddressOfIndex;
  mpp::u64 AddressOfCallBacks;
  mpp::u32 SizeOfZeroFill;
  mpp::u32 Characteristics;
};

} // namespace winlib
