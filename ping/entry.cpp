#include "memory.h"

int main()
{
	memory.initalize_driver();
	for (int i = 0; i < 10; i++) {
		memory.ping();
	}

	Sleep(-1);
}