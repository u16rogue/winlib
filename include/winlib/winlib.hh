#pragma once

#include "defs.hh"
#include <metapp/metapp.hh>

namespace winlib {

auto get_peb64() -> PEB64 *;
auto get_ntheaders64(void * base) -> NTHeaders64 *;

template <typename T>
auto enumerate_ldr_entry(T && cb) -> bool {
  PEB64 * peb = get_peb64();

  if (!peb) {
    return false;
  }

  for (LDRDataTableEntry64 * first_entry = nullptr, * current = peb->ldr_data->entry_order_load; current && current != first_entry; current = current->next) {
    if (!first_entry) {
      first_entry = current;
    }

    if (!current->base_address || !current->name.buff) {
      continue;
    }

    if (!cb(current)) {
      break;
    }
  }

  return true;
}

template <typename T>
auto enumerate_exports(void * base, T && cb) -> bool {
  NTHeaders64 * nt = get_ntheaders64(base);

  mpp::u8 * base8 = reinterpret_cast<decltype(base8)>(base);
  ExportDirectory * export_directory = reinterpret_cast<decltype(export_directory)>(base8 + nt->DataDirectory[_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  mpp::u32 * name = reinterpret_cast<decltype(name)>(base8 + export_directory->AddressOfNames);
  mpp::u32 * func = reinterpret_cast<decltype(func)>(base8 + export_directory->AddressOfFunctions);
  mpp::u16 * ords = reinterpret_cast<decltype(ords)>(base8 + export_directory->AddressOfNameOrdinals);

  for (mpp::u32 i = 0; i < export_directory->NumberOfNames; ++i) {
    if (!cb( reinterpret_cast<void *>(base8 + func[ords[i]]), reinterpret_cast<const char *>(base8 + name[i]) )) {
      break;
    }
  }

  return true;
}

template <typename T>
auto enumerate_sections(void * base, T && cb) -> bool {
  if (!base) {
    return false;
  }

  NTHeaders64   * ntheaders = get_ntheaders64(base);
  SectionHeader * sections  = reinterpret_cast<decltype(sections)>(ntheaders + 1);
  for (mpp::u32 i = 0; i < ntheaders->NumberOfSections; ++i) {
    if (!cb(&sections[i])) {
      break;
    }
  }

  return true;
}

template <typename T>
auto enumerate_module_imports(void * base, T && cb) -> bool {
  NTHeaders64 * nt = get_ntheaders64(base);

  mpp::u8 * base8 = reinterpret_cast<decltype(base8)>(base);
  const auto [dva, dsz] = nt->DataDirectory[_IMAGE_DIRECTORY_ENTRY_IMPORT];
  const void * const end = base8 + dva + dsz;
  
  for (ImportDescriptor * current = reinterpret_cast<decltype(current)>(base8 + dva); current < end && current->Name != 0; ++current) {
    if (!cb(current)) {
      break;
    }
  }

  return true;
}

template <typename T>
auto enumerate_import_descriptor_libimports(void * base, ImportDescriptor * descriptor, T && cb) -> bool {
  mpp::u8 * const baseu8 = reinterpret_cast<decltype(baseu8)>(base);
  mpp::u64 * ident = reinterpret_cast<decltype(ident)>(baseu8 + descriptor->OriginalFirstThunk);
  void **    pfn   = reinterpret_cast<decltype(pfn)>(baseu8 + descriptor->FirstThunk);

  for (; *ident; ++ident, ++pfn) {
    const char * id;
    if ((*ident & 0x8000000000000000ULL) != 0) {
      id = (const char *)(*ident & 0x000000000000FFFF); // Import by ordinal
    } else {
      id = reinterpret_cast<ImportByNameInfo *>(baseu8 + *ident)->Name; // Import by name
    }

    if (!cb(id, pfn)) {
      break;
    }
  }

  return true;
}

auto is_libimport_id_string(const char * id) -> bool;
auto get_descriptor_libname(void * base, ImportDescriptor * descriptor) -> const char *;
auto find_export(void * base, mpp::CmpHStr name) -> void *;
auto rva_to_fo(void * base, mpp::u64 rva) -> mpp::u64;
auto fo_to_rva(void * base, mpp::u64 ro) -> mpp::u64;

} // namespace winlib
