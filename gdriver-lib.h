#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <vector>
#include <tlhelp32.h>

#pragma comment( lib, "ntdll.lib" )

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG UniqueProcessId;
	ULONG HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	ULONG Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

#pragma pack ( push, 1 )
typedef struct _MAP
{
	unsigned long	type;
	unsigned long	slmbus;
	uintptr_t		address;
	unsigned long	iospace;
	unsigned long	size;
} MAP;
#pragma pack ( pop )

class gdriver_lib {
private:
	HANDLE hHandle = NULL;

#define MAP_MEM			3276808196
#define UNMAP_MEM		3276808200

	uintptr_t EP_DIRECTORYTABLE = 0x028;
	uintptr_t EP_UNIQUEPROCESSID = 0;
	uintptr_t EP_ACTIVEPROCESSLINK = 0;
	uintptr_t EP_VIRTUALSIZE = 0;
	uintptr_t EP_SECTIONBASE = 0;
	uintptr_t EP_IMAGEFILENAME = 0;

public:
	uintptr_t cr3 = 0;

	gdriver_lib()
	{
		hHandle = CreateFile("\\\\.\\GIO", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (hHandle == INVALID_HANDLE_VALUE)
			exit(5000);
	}
	~gdriver_lib() {
		CloseHandle(hHandle);
	}

	void get_eprocess_offsets();

	uintptr_t get_process_id(const char* image_name);
	uintptr_t get_process_base(const char* image_name);

	uintptr_t get_system_dirbase();
	uintptr_t leak_kprocess();
	bool leak_kpointers(std::vector<uintptr_t>& pointers);


	uintptr_t map_physical(uintptr_t physical_address, unsigned long size);
	uintptr_t unmap_physical(uintptr_t address);

	bool read_physical_memory(uintptr_t physical_address, void* out, unsigned long size);
	bool write_physical_memory(uintptr_t physical_address, void* data, unsigned long size);
	bool read_virtual_memory(uintptr_t address, LPVOID output, unsigned long size);
	bool write_virtual_memory(uintptr_t address, LPVOID data, unsigned long size);

	uintptr_t convert_virtual_to_physical(uintptr_t virtual_address);

	template<typename T>
	T read_virtual_memory(uintptr_t address)
	{
		T buffer;

		if (!read_virtual_memory(address, &buffer, sizeof(T)))
			return NULL;

		return buffer;
	}

	template<typename T>
	void write_virtual_memory(uintptr_t address, T val) {
		write_virtual_memory(address, (LPVOID)&val, sizeof(T));
	}

};

static gdriver_lib* gdriver = new gdriver_lib();