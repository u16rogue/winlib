#include <winlib/winlib.hh>

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
  mpp::u64 result = rva;

  NTHeaders64 * ntheader = get_ntheaders64(base);
  if (!ntheader) {
    return 0;
  }

  if (ntheader->SizeOfHeaders < rva) {
    return result;
  }

  enumerate_sections(base, [&](SectionHeader * section) -> bool {
    // We use SizeOfRawData as having an RVA that lands on a padded section we wont be able to properly
    // index it as a file offset
    if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData) {
      result = (rva - section->VirtualAddress) + section->PointerToRawData;
      return false;
    }
    return true;
  });

  return result;
}

auto winlib::fo_to_rva(void * base, mpp::u64 fo) -> mpp::u64 {
  mpp::u64 result = fo;

  NTHeaders64 * ntheader = get_ntheaders64(base);
  if (!ntheader) {
    return 0;
  }

  if (ntheader->SizeOfHeaders < fo) {
    return result;
  }

  enumerate_sections(base, [&](SectionHeader * section) -> bool {
    // We use SizeOfRawData as having an RVA that lands on a padded section we wont be able to properly
    // index it as a file offset
    if (fo >= section->PointerToRawData && fo < section->PointerToRawData + section->SizeOfRawData) {
      result = (fo - section->PointerToRawData) + section->VirtualAddress;
      return false;
    }
    return true;
  });

  return result;
}
