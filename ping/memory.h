#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

class mahirjack
{
private:
	HANDLE handle;
public:
	bool initalize_driver() {
		handle = CreateFileW(L"\\\\.\\GLOBALROOT\\Device\\BTHMS_RFCOMM", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!handle || (handle == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	void ping() {
		DeviceIoControl(handle, 0x3169, NULL, NULL, nullptr, 0, nullptr, nullptr);
	}
};

inline mahirjack memory;