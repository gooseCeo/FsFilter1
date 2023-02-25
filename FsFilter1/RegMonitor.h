#include "stdio.h"
#include <ntifs.h>


typedef struct _GLOBAL_CONTEXT {
	PDRIVER_OBJECT DriverObject;
	UNICODE_STRING Altitude;
	LARGE_INTEGER Cookie;
} GLOBAL_CONTEXT, *PGLOBAL_CONTEXT;

GLOBAL_CONTEXT g_GlobalContext = { 0 };

UNICODE_STRING g_PolicyKeyArray[] = {
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Services\\myDriver"),
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\ControlSet001\\Services\\myDriver"),
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\ControlSet002\\Services\\myDriver"),
	RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\System\\ControlSet003\\Services\\myDriver")
};
ULONG g_PolicyKeyCount = sizeof(g_PolicyKeyArray) / sizeof(UNICODE_STRING);


BOOLEAN
CheckProcess(VOID) {
	PEPROCESS  Process;
	//PCHAR ImageFileName;

	Process = PsGetCurrentProcess();
	/*
	//ImageFileName = PsGetProcessImageFileName(Process);
	PUNICODE_STRING processImageName = PsGetProcessImageFileNameEx(Process);

	// UNICODE_STRING을 WCHAR 배열로 변환
	WCHAR imageName[256];
	RtlZeroMemory(imageName, sizeof(imageName));
	wcsncpy(imageName, processImageName->Buffer, processImageName->Length / sizeof(WCHAR));

	if (_stricmp(imageName, "services.exe") == 0) {
		return TRUE;
	}

	if (_stricmp(imageName, "svchost.exe") == 0) {
		return TRUE;
	}
	*/
	return FALSE;
}


BOOLEAN CheckPolicy(PUNICODE_STRING KeyFullPath) {

	BOOLEAN Matched = FALSE;
	ULONG Idx;
	if (KeyFullPath && KeyFullPath->Buffer)
	{
		DbgPrint("[ dmjoo ] (%x) path: %S\n", PsGetCurrentProcessId(), KeyFullPath->Buffer);
	}

	
	for (Idx = 0; Idx < g_PolicyKeyCount; Idx++) {
		if (RtlEqualUnicodeString(KeyFullPath, &g_PolicyKeyArray[Idx], TRUE)) {
			Matched = TRUE;
			break;
		}
	}

	if (Matched) {
		DbgPrint("[ RegMonitor ] pid(%x) and tid(%x) Block %wZ\n",
			PsGetCurrentProcessId(), PsGetCurrentThreadId(), KeyFullPath);
	}

	return Matched;
}


NTSTATUS RegPreDeleteKey(PVOID RootObject, PUNICODE_STRING CompleteName)
{
	PUNICODE_STRING RootObjectName;
	ULONG_PTR RootObjectID;
	BOOLEAN Matched = FALSE;
	NTSTATUS Status;
	UNICODE_STRING KeyPath = { 0 };

	// CompleteName can have a absolute path or relative path.
	// That's why we should do more work.

	// If RootObject is not valid, It means CompleteName has full path.
	// If RootObject is valid, we should work more.
	if (RootObject) {

		// We store path from RootObject to RootObjectName using CmCallbackGetKeyObjectID()
		if (!NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RootObject, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[ RegMonitor ] [ ERROR ] CmCallbackGetKeyObjectID : %x\n", Status);
			goto Exit;
		}

		// If there is valid CompleteName, we should concatenate RootObjectName and CompleteName.
		// If there isn't, just use RootObjectName.
		if (CompleteName->Length && CompleteName->Buffer) {

			KeyPath.MaximumLength = RootObjectName->Length + CompleteName->Length + (sizeof(WCHAR) * 2);

			KeyPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, KeyPath.MaximumLength, 'pkMC');

			if (!KeyPath.Buffer) {
				DbgPrint("[ RegMonitor ] [ Error ] ExAllocatePool() FAIL\n");
				goto Exit;
			}
			//DbgPrint("[dmjoo]%S\\%S", RootObjectName->Buffer, CompleteName->Buffer);
			swprintf(KeyPath.Buffer, L"%wZ\\%wZ", RootObjectName, CompleteName);
			//swprintf(KeyPath.Buffer, L"%S\\%S", RootObjectName, CompleteName);
			
			KeyPath.Length = RootObjectName->Length + CompleteName->Length + (sizeof(WCHAR));

			Matched = CheckPolicy(&KeyPath);
		}
		else {
			//Matched = CheckPolicy(RootObjectName);

		}
	}
	else {
		//Matched = CheckPolicy(CompleteName);
	}

Exit:
	// if a buffer was allocated in KeyPath.Buffer then free it 
	if (KeyPath.Buffer) {
		ExFreePool(KeyPath.Buffer);
	}
	return Matched;
}


NTSTATUS RegistryFilterCallback(
	IN PVOID               CallbackContext,
	IN PVOID               Argument1,
	IN PVOID               Argument2
) {
	NTSTATUS Status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	PUNICODE_STRING RootObjectName;
	ULONG_PTR RootObjectID;
	UNREFERENCED_PARAMETER(CallbackContext);

	/*
	if (CheckProcess()) {
		return STATUS_SUCCESS;
	}
	*/
	
	if (RegNtRenameKey == NotifyClass )
	{		
		PREG_RENAME_KEY_INFORMATION RegInformation = (PREG_RENAME_KEY_INFORMATION)Argument2;
		//DbgPrint("[ dmjoo start] %d %s\n", NotifyClass, RegInformation->CompleteName->Buffer);
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:rename] %wZ -> %wZ\n", RootObjectName, RegInformation->NewName);
		}
		
	}
	else if (RegNtDeleteKey == NotifyClass) {
		PREG_DELETE_KEY_INFORMATION RegInformation = (PREG_DELETE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:delete] %wZ\n", RootObjectName);
		}
	}
	else if (RegNtDeleteValueKey == NotifyClass) {
		PREG_DELETE_VALUE_KEY_INFORMATION RegInformation = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:deleteValueKey] %wZ\n", RootObjectName, RegInformation->ValueName);
		}
	}
	
	return Status;
}


NTSTATUS InstallRegMonitor(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	RtlInitUnicodeString(&g_GlobalContext.Altitude, L"140831");
	g_GlobalContext.DriverObject = DriverObject;

	if (!NT_SUCCESS(Status = CmRegisterCallbackEx(
		RegistryFilterCallback,
		&g_GlobalContext.Altitude,
		DriverObject,
		&g_GlobalContext,
		&g_GlobalContext.Cookie,
		NULL
	))) {
		DbgPrint("[ RegMonitor ] [ ERROR ] CmRegisterCallbackEx Failed : (%x)\n", Status);
		return Status;
	} else {
		DbgPrint("[ RegMonitor ] [ SUCCESS ] CmRegisterCallbackEx Success\n");
	}

	return STATUS_SUCCESS;
}


NTSTATUS UnInstallRegMonitor()
{
	NTSTATUS Status;

	if (!NT_SUCCESS(Status = CmUnRegisterCallback(g_GlobalContext.Cookie))) {
		DbgPrint("[ RegMonitor ] [ ERROR ] CmUnRegisterCallback Failed (%x)\n", Status);
		return Status;
	} else {
		DbgPrint("[ RegMonitor ] [ SUCCESS ] CmUnRegisterCallback Success\n");
	}
	return STATUS_SUCCESS;
}

