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
  if (!nt) {
    return false;
  }

  mpp::u8 * base8 = reinterpret_cast<decltype(base8)>(base);
  ExportDirectory * export_directory = reinterpret_cast<decltype(export_directory)>(base8 + nt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

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

auto find_export(void * base, mpp::CmpHStr name) -> void *;

} // namespace winlib
