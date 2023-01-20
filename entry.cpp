#include "gdriver-lib.h"

int main()
{
	uintptr_t base = gdriver->get_process_base("explorer.exe");

	if (!base)
	{
		printf("[-] process is not running\n");
		return false;
	}

	auto test = gdriver->read_virtual_memory<uintptr_t>(base);

	printf("read: %llx\n", test);

	getchar();

	return true;
}