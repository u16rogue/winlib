#include <winlib/winlib.hh>
#include <memory>

auto winlib::get_peb64() -> PEB64 * {
  void * pp = nullptr;
  __asm__(R"(
      mov %%gs:0x60, %0
    )"
    : "=r" (pp)
  );
  return reinterpret_cast<PEB64 *>(pp);
}

auto winlib::get_ntheaders64(void * base) -> NTHeaders64 * {
  return reinterpret_cast<NTHeaders64 *>(reinterpret_cast<mpp::u8 *>(base) + reinterpret_cast<DOSHeader *>(base)->e_lfanew);
}

auto winlib::find_export(void * base, mpp::CmpHStr name) -> void * {
  void * fnp = nullptr;
  enumerate_exports(base, [&](void * p, const char * pname) -> bool {
    if (name == pname) {
      fnp = p;
      return false;
    }
    return true;
  });
  return fnp;
}

auto winlib::rva_to_fo(void * base, mpp::u64 rva) -> mpp::u64 {
  mpp::u64 result = 0;

  NTHeaders64 * ntheader = get_ntheaders64(base);
  if (!ntheader) {
    return 0;
  }

  enumerate_sections(base, [&](SectionHeader * section) -> bool {
    if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData) {
      result = section->PointerToRawData + (rva - section->VirtualAddress);
      return false;
    }
    return true;
  });

  return result;
}

auto winlib::fo_to_rva(void * base, mpp::u64 fo) -> mpp::u64 {
  mpp::u64 result = 0;

  NTHeaders64 * ntheader = get_ntheaders64(base);
  if (!ntheader) {
    return 0;
  }

  enumerate_sections(base, [&](SectionHeader * section) -> bool {
    if (fo >= section->PointerToRawData && fo < section->PointerToRawData + section->SizeOfRawData) {
      result = section->VirtualAddress + (fo - section->PointerToRawData);
      return false;
    }
    return true;
  });

  return result;
}


auto winlib::get_descriptor_libname(void * base, ImportDescriptor * descriptor) -> const char * {
  return reinterpret_cast<const char *>(base) + descriptor->Name;
}

auto winlib::is_libimport_id_string(const char * id) -> bool {
  return std::bit_cast<mpp::u64>(&id) & 0xFFFFFFFFFFFF0000;
}
