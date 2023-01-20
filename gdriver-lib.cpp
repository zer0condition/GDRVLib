#include "gdriver-lib.h"

void gdriver_lib::get_eprocess_offsets() {

	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	OSVERSIONINFOEXW osInfo;

	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"),
		"RtlGetVersion");

	DWORD build = 0;

	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		build = osInfo.dwBuildNumber;
	}

	switch (build) 
	{
	case 22000: //WIN11
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19044: //WIN10_21H2
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19043: //WIN10_21H1
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19042: //WIN10_20H2
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19041: //WIN10_20H1
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 18363: //WIN10_19H2
		EP_UNIQUEPROCESSID = 0x2e8;
		EP_ACTIVEPROCESSLINK = 0x2f0;
		EP_VIRTUALSIZE = 0x340;
		EP_SECTIONBASE = 0x3c8;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 18362: //WIN10_19H1
		EP_UNIQUEPROCESSID = 0x2e8;
		EP_ACTIVEPROCESSLINK = 0x2f0;
		EP_VIRTUALSIZE = 0x340;
		EP_SECTIONBASE = 0x3c8;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 17763: //WIN10_RS5
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 17134: //WIN10_RS4
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 16299: //WIN10_RS3
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 15063: //WIN10_RS2
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 14393: //WIN10_RS1
		EP_UNIQUEPROCESSID = 0x2e8;
		EP_ACTIVEPROCESSLINK = 0x2f0;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	default:
		exit(0);
		break;
	}
}




uintptr_t gdriver_lib::leak_kprocess()
{
	std::vector<uintptr_t> pointers;

	if (!leak_kpointers(pointers))
	{
		return false;
	}

	const unsigned int sanity_check = 0x3;

	for (uintptr_t pointer : pointers)
	{
		unsigned int check = 0;

		read_virtual_memory(pointer, &check, sizeof(unsigned int));

		if (check == sanity_check)
		{
			return pointer;
			break;
		}
	}

	return NULL;
}


bool gdriver_lib::leak_kpointers(std::vector<uintptr_t>& pointers)
{
	const unsigned long SystemExtendedHandleInformation = 0x40;

	unsigned long buffer_length = 0;
	unsigned char tempbuffer[1024] = { 0 };
	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), &tempbuffer, sizeof(tempbuffer), &buffer_length);

	buffer_length += 50 * (sizeof(SYSTEM_HANDLE_INFORMATION_EX) + sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

	PVOID buffer = VirtualAlloc(nullptr, buffer_length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	RtlSecureZeroMemory(buffer, buffer_length);

	unsigned long buffer_length_correct = 0;
	status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemExtendedHandleInformation), buffer, buffer_length, &buffer_length_correct);

	SYSTEM_HANDLE_INFORMATION_EX* handle_information = reinterpret_cast<SYSTEM_HANDLE_INFORMATION_EX*>(buffer);

	for (unsigned int i = 0; i < handle_information->NumberOfHandles; i++)
	{
		const unsigned int SystemUniqueReserved = 4;
		const unsigned int SystemKProcessHandleAttributes = 0x102A;

		if (handle_information->Handles[i].UniqueProcessId == SystemUniqueReserved &&
			handle_information->Handles[i].HandleAttributes == SystemKProcessHandleAttributes)
		{
			pointers.push_back(reinterpret_cast<uintptr_t>(handle_information->Handles[i].Object));
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return true;
}


uintptr_t gdriver_lib::map_physical(uintptr_t physical_address, unsigned long size)
{
	MAP in_buffer = { 0, 0, physical_address, 0, size };
	uintptr_t out_buffer[2] = { 0 };

	unsigned long returned = 0;

	DeviceIoControl(hHandle, MAP_MEM, reinterpret_cast<LPVOID>(&in_buffer), sizeof(in_buffer),
		reinterpret_cast<LPVOID>(out_buffer), sizeof(out_buffer), &returned, NULL);

	return out_buffer[0];
}

uintptr_t gdriver_lib::unmap_physical(uintptr_t address)
{
	uintptr_t in_buffer = address;
	uintptr_t out_buffer[2] = { 0 };

	unsigned long returned = 0;

	DeviceIoControl(hHandle, UNMAP_MEM, reinterpret_cast<LPVOID>(&in_buffer), sizeof(in_buffer),
		reinterpret_cast<LPVOID>(out_buffer), sizeof(out_buffer), &returned, NULL);

	return out_buffer[0];
}

uintptr_t gdriver_lib::get_system_dirbase()
{
	for (int i = 0; i < 10; i++)
	{
		uintptr_t lpBuffer = map_physical(i * 0x10000, 0x10000);

		for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
		{

			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0))
				continue;

			return *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0);
		}

		unmap_physical(lpBuffer);
	}

	return NULL;
}

uintptr_t gdriver_lib::get_process_id(const char* image_name)
{
	HANDLE hsnap;
	PROCESSENTRY32 pt;
	DWORD PiD;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (!strcmp(pt.szExeFile, image_name)) {
			CloseHandle(hsnap);
			PiD = pt.th32ProcessID;
			return PiD;
			if (PiD != NULL) {
				return 0;
			}
		}
	} while (Process32Next(hsnap, &pt));
	return 1;
}

uintptr_t gdriver_lib::get_process_base(const char* image_name)
{
	get_eprocess_offsets();

	cr3 = get_system_dirbase();

	if (!cr3)
		return NULL;

	uintptr_t kprocess_initial = leak_kprocess();

	if (!kprocess_initial)
		return NULL;

	printf("system_kprocess: %llx\n", kprocess_initial);
	printf("system_cr3: %llx\n", cr3);

	const unsigned long limit = 400;

	uintptr_t link_start = kprocess_initial + EP_ACTIVEPROCESSLINK;
	uintptr_t flink = link_start;
	uintptr_t image_base_out = 0;


	for (int a = 0; a < limit; a++)

	{
		read_virtual_memory(flink, &flink, sizeof(PVOID));

		uintptr_t kprocess = flink - EP_ACTIVEPROCESSLINK;
		uintptr_t virtual_size = read_virtual_memory<uintptr_t>(kprocess + EP_VIRTUALSIZE);

		if (virtual_size == 0)
			continue;

		uintptr_t directory_table = read_virtual_memory<uintptr_t>(kprocess + EP_DIRECTORYTABLE);
		uintptr_t base_address = read_virtual_memory<uintptr_t>(kprocess + EP_SECTIONBASE);

		char name[16] = { };
		read_virtual_memory(kprocess + EP_IMAGEFILENAME, &name, sizeof(name));

		int process_id = 0;
		read_virtual_memory(kprocess + EP_UNIQUEPROCESSID, &process_id, sizeof(process_id));

		if (strstr(image_name, name) && process_id == get_process_id(image_name))
		{
			printf("process_id: %i\n", process_id);
			printf("process_base: %llx\n", base_address);
			printf("process_cr3: %llx\n", directory_table);

			image_base_out = base_address;
			cr3 = directory_table;

			break;
		}
	}

	return image_base_out;
}


bool gdriver_lib::read_physical_memory(uintptr_t physical_address, void* output, unsigned long size)
{
	uintptr_t virtual_address = map_physical(physical_address, size);

	if (!virtual_address)
		return false;

	memcpy(output, reinterpret_cast<LPCVOID>(virtual_address), size);
	unmap_physical(virtual_address);
	return true;
}

bool gdriver_lib::write_physical_memory(uintptr_t physical_address, void* data, unsigned long size)
{
	if (!data)
		return false;

	uintptr_t virtual_address = map_physical(physical_address, size);

	if (!virtual_address)
		return false;

	memcpy(reinterpret_cast<LPVOID>(virtual_address), reinterpret_cast<LPCVOID>(data), size);
	unmap_physical(virtual_address);
	return true;
}

uintptr_t gdriver_lib::convert_virtual_to_physical(uintptr_t virtual_address)
{
	uintptr_t va = virtual_address;

	unsigned short PML4 = (unsigned short)((va >> 39) & 0x1FF);
	uintptr_t PML4E = 0;
	read_physical_memory((cr3 + PML4 * sizeof(uintptr_t)), &PML4E, sizeof(PML4E));

	unsigned short DirectoryPtr = (unsigned short)((va >> 30) & 0x1FF);
	uintptr_t PDPTE = 0;
	read_physical_memory(((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), &PDPTE, sizeof(PDPTE));

	if ((PDPTE & (1 << 7)) != 0)
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);

	unsigned short Directory = (unsigned short)((va >> 21) & 0x1FF);

	uintptr_t PDE = 0;
	read_physical_memory(((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), &PDE, sizeof(PDE));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	unsigned short Table = (unsigned short)((va >> 12) & 0x1FF);
	uintptr_t PTE = 0;

	read_physical_memory(((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), &PTE, sizeof(PTE));

	if (PTE == 0)
		return 0;

	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}

bool gdriver_lib::read_virtual_memory(uintptr_t address, LPVOID output, unsigned long size)
{
	if (!address)
		return false;

	if (!size)
		return false;

	uintptr_t physical_address = convert_virtual_to_physical(address);

	if (!physical_address)
		return false;

	read_physical_memory(physical_address, output, size);
	return true;
}

bool gdriver_lib::write_virtual_memory(uintptr_t address, LPVOID data, unsigned long size)
{
	uintptr_t physical_address = convert_virtual_to_physical(address);

	if (!physical_address)
		return false;

	write_physical_memory(physical_address, data, size);
	return true;
}