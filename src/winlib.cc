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
