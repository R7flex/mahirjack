#include "utils.hpp"

NTSTATUS my_dispatch(const PDEVICE_OBJECT device_object, const PIRP irp)
{
	NTSTATUS status{};
	unsigned long bytes{};

	auto* const ioc = IoGetCurrentIrpStackLocation(irp);
	auto* const io_buffer = irp->AssociatedIrp.SystemBuffer;

	const auto input_buffer_length = ioc->Parameters.DeviceIoControl.InputBufferLength;
	const auto io_control_code = ioc->Parameters.DeviceIoControl.IoControlCode;

	printf("mahirjacked!\n");
	
	return status;
}

NTSTATUS driver_entry(uint64_t base, uint32_t size) {
	NTSTATUS status = STATUS_SUCCESS;

	const uint64_t rfcomm_module = utils::get_kernel_module(crypt("rfcomm.sys"));
	if (!rfcomm_module) {
		status = STATUS_UNSUCCESSFUL;
		printf("driver can't found rfcomm.sys! returned 0x%llx", status);
		return status;
	}

	printf("rfcomm module base: 0x%llx", rfcomm_module);

	const uint64_t rfcomm_dispatch = utils::pattern_scan(rfcomm_module, crypt("\x4C\x89\x4C\x24\x00\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57"), crypt("xxxx?xxxxxxxxxxxx"));
	if (!rfcomm_dispatch) {
		status = STATUS_UNSUCCESSFUL;
		printf("driver can't found rfcomm dispatch! returned 0x%llx", status);
		return status;
	}

	printf("rfcomm dispatch: 0x%llx", rfcomm_dispatch);

	BYTE shell_code[] = { 0x48 ,0x89 ,0x54 ,0x24 ,0x10 ,0x48 ,0x89 ,0x4C ,0x24 ,0x08 ,0x48 ,0x83 ,0xEC ,0x38 ,0x48 ,0xB8 ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0x7F ,0x48 ,0x89 ,0x44 ,0x24 ,0x20 ,0x48 ,0x8B ,0x54 ,0x24 ,0x48 ,0x48 ,0x8B ,0x4C ,0x24 ,0x40 ,0xFF ,0x54 ,0x24 ,0x20 ,0x48 ,0x83 ,0xC4 ,0x38 ,0xC3 };
	auto* code_buffer = ExAllocatePool(NonPagedPool, sizeof(shell_code));
	if (!code_buffer) {
		status = STATUS_UNSUCCESSFUL;
		printf("driver can't allocate! returned 0x%llx", status);
		return status;
	}

	memcpy(code_buffer, shell_code, sizeof(shell_code));
	*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(code_buffer) + 16) = (uintptr_t)&my_dispatch;

	bool success = utils::my_write(reinterpret_cast<void*>(rfcomm_dispatch), code_buffer, sizeof(shell_code));
	if (!success) {
		status = STATUS_UNSUCCESSFUL;
		printf("driver can't copy shell! returned 0x%llx", status);
		return status;
	}

	ExFreePoolWithTag(code_buffer, 0);
	return status;
}