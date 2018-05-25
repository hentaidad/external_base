#include "utilities.h"
#include "lazy_importer.hpp"

auto base = reinterpret_cast<uintptr_t>(LI_FIND(LoadLibraryA)("Kernel32.dll"));

utilities g_Utils;

ULONG utilities::get_pid(const std::string &_process)
{
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Snapshot == INVALID_HANDLE_VALUE)
		return NULL;

	PROCESSENTRY32 _pEntry;
	_pEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(Snapshot, &_pEntry))
	{
		CloseHandle(Snapshot);
		return NULL;
	}

	do
	{
		if (!_process.compare(_pEntry.szExeFile))
		{
			CloseHandle(Snapshot);
			return _pEntry.th32ProcessID;
		}
	} while (Process32Next(Snapshot, &_pEntry));

	CloseHandle(Snapshot);

	return NULL;
}

HWND utilities::get_window(const LPCSTR &_windowName)
{
	HWND hWindow = FindWindowA(NULL, _windowName);

	if (hWindow == INVALID_HANDLE_VALUE)
		return NULL;

	return hWindow;
}

HANDLE utilities::get_handle(const ULONG &_processId, const ULONG &_desiredAccess, bool _protect)
{
	HANDLE hProcess = OpenProcess(_desiredAccess, false, _processId);

	if (hProcess == INVALID_HANDLE_VALUE)
		return NULL;

	if (_protect == true)
	{
		if (SetHandleInformation(hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0)
			return hProcess;
	}

	return hProcess;
}

uintptr_t utilities::get_base(const ULONG &_processId, const TCHAR *_module)
{
	uintptr_t modBase = 0;

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, _processId);

	if (Snapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 ModEntry32;
		ModEntry32.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(Snapshot, &ModEntry32))
		{
			do {
				if (_tcsicmp(ModEntry32.szModule, _module) == 0)
				{
					modBase = (uintptr_t)ModEntry32.modBaseAddr;
					break;
				}
			} while (Module32Next(Snapshot, &ModEntry32));
		}
		CloseHandle(Snapshot);
	}

	return modBase;
}

void utilities::erase_pe()
{
	ULONG old_prot = 0;
	char *Base = (char*)GetModuleHandleA(NULL);
	VirtualProtect(Base, 4096, PAGE_READWRITE, &old_prot);
	RtlSecureZeroMemory(Base, 4096);
}

bool utilities::set_debug(bool _status)
{
	HANDLE hToken = INVALID_HANDLE_VALUE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	TOKEN_PRIVILEGES TokenPriv = { NULL };
	TokenPriv.PrivilegeCount = 1;
	TokenPriv.Privileges[0].Attributes = _status ? SE_PRIVILEGE_ENABLED : 0;

	if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &TokenPriv.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return false;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPriv, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);

	return true;
}

ULONG utilities::find_pattern(HANDLE _handle, ULONG _base, ULONG _len, BYTE* _pat, char* _mask, int _offset)
{
	BYTE* buffer = (BYTE*)VirtualAlloc(0, _len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (ReadProcessMemory(_handle, (LPCVOID)_base, buffer, _len, NULL) == false)
	{
		char buffer2[64];
		return NULL;
	}

	for (int i = 0;
		i <= (_len - strlen(_mask)) + 1;
		i++)
	{
		if ((buffer[i] == _pat[0] && _mask[0] == 'x') || (_mask[0] == '?'))
		{
			for (int x = 0;
				;
				x++)
			{
				if (_mask[x] == 'x')
				{
					if (buffer[i + x] == _pat[x])
						continue;
					else
						break;
				}
				else if (_mask[x] == 0x00) {
					return (ULONG)(_base + i + _offset);
				}
			}
		}
	}

	return NULL;
}

bool utilities::nop_bytes(HANDLE _handle, uintptr_t _address, SIZE_T _size)
{
	BYTE * nops = new BYTE[_size];
	memset(nops, 0x90, _size);
	
	BOOL ret = WriteProcessMemory(_handle, reinterpret_cast<void*>(_address), nops, _size, nullptr);

	delete[] nops;

	return (ret == 1);
}

template <typename T> T utilities::RPM(HANDLE _handle, SIZE_T _address)
{
	T buffer;
	ReadProcessMemory(_handle, (LPCVOID)_address, &buffer, sizeof(T), NULL);
	return buffer;
}

template <typename T> T utilities::WPM(HANDLE _handle, SIZE_T _address, T _data)
{
	if (address == nullptr)
		return;

	WriteProcessMemory(_handle, (LPVOID)_address, &_data, sizeof(_data), NULL);
}