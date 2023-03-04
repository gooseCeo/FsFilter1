#include "stdio.h"
#include <ntifs.h>
#include "regfltr.h"
#include <ntddk.h>
#include <tchar.h>

#define MAX_KEY_LENGTH 256
void countRegList(PHANDLE hkey);
UNICODE_STRING ParseRegistryKey(PUNICODE_STRING registryKey);
NTSTATUS RegisterRegistryKey(PUNICODE_STRING valueName, PUNICODE_STRING data);
NTSTATUS GetProcessIdString(OUT PUNICODE_STRING ProcessIdString);
void getRegValue();
NTSTATUS getRegList(PUNICODE_STRING keyName);
NTSTATUS BackupRegistryKey(PUNICODE_STRING keyPath, PLARGE_INTEGER microtime);
NTSTATUS EnumerateValueNames(PUNICODE_STRING RegistryKey);

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


#define PROCESS_IMAGE_NAME_LENGTH 1024

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

LPCWSTR
GetNotifyClassString(
	_In_ REG_NOTIFY_CLASS NotifyClass
)
/*++

Routine Description:

	Converts from NotifyClass to a string

Arguments:

	NotifyClass - value that identifies the type of registry operation that
		is being performed

Return Value:

	Returns a string of the name of NotifyClass.

--*/
{
	switch (NotifyClass) {
		/*
			RegNtPreCreateKey,
			RegNtPostCreateKey,
			RegNtPreOpenKey,
			RegNtPostOpenKey,
		*/

			
	case RegNtPreDeleteKey:               return L"RegNtPreDeleteKey";
	case RegNtPreSetValueKey:            return L"RegNtPreSetValueKey";
	case RegNtPreDeleteValueKey:         return L"RegNtPreDeleteValueKey";
	case RegNtPreSetInformationKey:         return L"RegNtPreSetInformationKey";
	case RegNtPreRenameKey:                 return L"RegNtPreRenameKey";
	case RegNtPreEnumerateKey:              return L"RegNtPreEnumerateKey";
	case RegNtPreEnumerateValueKey:         return L"RegNtPreEnumerateValueKey";
	case RegNtPreQueryKey:                  return L"RegNtPreQueryKey";
	case RegNtPreQueryValueKey:             return L"RegNtPreQueryValueKey";
	case RegNtPreQueryMultipleValueKey:     return L"RegNtPreQueryMultipleValueKey";
	case RegNtPreKeyHandleClose:            return L"RegNtPreKeyHandleClose";
	case RegNtPreCreateKeyEx:               return L"RegNtPreCreateKeyEx";
	case RegNtPreOpenKeyEx:                 return L"RegNtPreOpenKeyEx";
	case RegNtPreFlushKey:                  return L"RegNtPreFlushKey";
	case RegNtPreLoadKey:                   return L"RegNtPreLoadKey";
	case RegNtPreUnLoadKey:                 return L"RegNtPreUnLoadKey";
	case RegNtPreQueryKeySecurity:          return L"RegNtPreQueryKeySecurity";
	case RegNtPreSetKeySecurity:            return L"RegNtPreSetKeySecurity";
	case RegNtPreRestoreKey:                return L"RegNtPreRestoreKey";
	case RegNtPreSaveKey:                   return L"RegNtPreSaveKey";
	case RegNtPreReplaceKey:                return L"RegNtPreReplaceKey";

	case RegNtPostDeleteKey:                return L"RegNtPostDeleteKey";
	case RegNtPostSetValueKey:              return L"RegNtPostSetValueKey";
	case RegNtPostDeleteValueKey:           return L"RegNtPostDeleteValueKey";
	case RegNtPostSetInformationKey:        return L"RegNtPostSetInformationKey";
	case RegNtPostRenameKey:                return L"RegNtPostRenameKey";
	case RegNtPostEnumerateKey:             return L"RegNtPostEnumerateKey";
	case RegNtPostEnumerateValueKey:        return L"RegNtPostEnumerateValueKey";
	case RegNtPostQueryKey:                 return L"RegNtPostQueryKey";
	case RegNtPostQueryValueKey:            return L"RegNtPostQueryValueKey";
	case RegNtPostQueryMultipleValueKey:    return L"RegNtPostQueryMultipleValueKey";
	case RegNtPostKeyHandleClose:           return L"RegNtPostKeyHandleClose";
	case RegNtPostCreateKeyEx:              return L"RegNtPostCreateKeyEx";
	case RegNtPostOpenKeyEx:                return L"RegNtPostOpenKeyEx";
	case RegNtPostFlushKey:                 return L"RegNtPostFlushKey";
	case RegNtPostLoadKey:                  return L"RegNtPostLoadKey";
	case RegNtPostUnLoadKey:                return L"RegNtPostUnLoadKey";
	case RegNtPostQueryKeySecurity:         return L"RegNtPostQueryKeySecurity";
	case RegNtPostSetKeySecurity:           return L"RegNtPostSetKeySecurity";
	case RegNtPostRestoreKey:               return L"RegNtPostRestoreKey";
	case RegNtPostSaveKey:                  return L"RegNtPostSaveKey";
	case RegNtPostReplaceKey:               return L"RegNtPostReplaceKey";
	case RegNtCallbackObjectContextCleanup: return L"RegNtCallbackObjectContextCleanup";

	case RegNtPreQueryKeyName: return L"RegNtPreQueryKeyName";
	case RegNtPostQueryKeyName: return L"RegNtPostQueryKeyName";

	default:
		return L"Unsupported REG_NOTIFY_CLASS";
	}
}

PLARGE_INTEGER g_CmCookie;

NTSTATUS RegistryFilterCallback(
	IN PVOID               CallbackContext,
	IN PVOID               Argument1,
	IN PVOID               Argument2
) {
	NTSTATUS Status = STATUS_SUCCESS;
	PCALLBACK_CONTEXT CallbackCtx;
	REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	PUNICODE_STRING RootObjectName;
	ULONG_PTR RootObjectID;	
	UNICODE_STRING valueName;
	//UNICODE_STRING data;
	WCHAR microtime[20] = { 0 };
	LARGE_INTEGER currentTime;
	CallbackCtx = (PCALLBACK_CONTEXT)CallbackContext;
	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	HANDLE pid = PsGetCurrentProcessId();
	UNICODE_STRING RegistryKey;

	if ((ULONGLONG)pid != 10492) return STATUS_SUCCESS;


	if (Argument2 == NULL ) {

		//
		// This should never happen but the sal annotation on the callback 
		// function marks Argument 2 as opt and is looser than what 
		// it actually is.
		//

		return STATUS_SUCCESS;
	}
	
	//InfoPrint("\t[dmjoo]%d Callback: callbackmode-%d, [%d]NotifyClass-%S.", pid, CallbackCtx->CallbackMode, NotifyClass, GetNotifyClassString(NotifyClass));
	
	
	
	if (RegNtRenameKey == NotifyClass )
	{		
		PREG_RENAME_KEY_INFORMATION RegInformation = (PREG_RENAME_KEY_INFORMATION)Argument2;
		//DbgPrint("[ dmjoo start] %d %s\n", NotifyClass, RegInformation->CompleteName->Buffer);
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:rename] %wZ -> %wZ\n", RootObjectName, RegInformation->NewName);

			//getRegList(RootObjectName);


			RtlInitUnicodeString(&RegistryKey, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\FuzzyDS");
			
			//EnumerateValueNames(&RegistryKey);
			EnumerateValueNames(RootObjectName);
		}		
	}	
	/*
	else if (RegNtPreCreateKeyEx == NotifyClass)
	{
		PREG_CREATE_KEY_INFORMATION  RegInformation = (PREG_CREATE_KEY_INFORMATION)Argument2;
		
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->RootObject, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:rename] %wZ -> %wZ\n", RootObjectName, RegInformation->CompleteName);
		}
	}
	*/
	else if (RegNtDeleteKey == NotifyClass) {
		PREG_DELETE_KEY_INFORMATION RegInformation = (PREG_DELETE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:delete] %wZ\n", RootObjectName);			
		}
		//getRegList(RootObjectName);
		

		

		// Get the current time
		KeQuerySystemTimePrecise(&currentTime);
		DbgPrint("[dmjoo:time] %llu\n", currentTime.QuadPart);
		swprintf_s(microtime, 20, L"%llu", currentTime.QuadPart);

		RtlInitUnicodeString(&valueName, microtime);
		RegisterRegistryKey(&valueName, RootObjectName);
		BackupRegistryKey(RootObjectName, &currentTime);
	}
	else if (RegNtDeleteValueKey == NotifyClass) {
		PREG_DELETE_VALUE_KEY_INFORMATION RegInformation = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:deleteValueKey] %wZ %wZ\n", RootObjectName, RegInformation->ValueName);
		}
		getRegValue(RootObjectName, RegInformation->ValueName);
	}
	
	else if (RegNtSetValueKey == NotifyClass) {
		PREG_SET_VALUE_KEY_INFORMATION RegInformation = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:SetValueKey] %wZ [%wZ]\n", RootObjectName, RegInformation->ValueName);
			//DbgPrint("[dmjoo:SetValueKey] %wZ[%wZ]\n", RegInformation->ValueName);
			if ( RegInformation->DataSize > 0 ) DbgPrint("[dmjoo:SetValueKey_Data] [%d:%d:%S]\n", RegInformation->Type, RegInformation->DataSize, RegInformation->Data);

			getRegValue(RootObjectName, RegInformation->ValueName);
		}
	}
	/*
	else if (RegNtSetValueKey == NotifyClass) {
		PREG_SET_VALUE_KEY_INFORMATION SetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, SetValueInfo->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("ValueName: %wZ", &SetValueInfo->ValueName);
			DbgPrint("Type: %d, DataSize: %d, Data: %p", SetValueInfo->Type, SetValueInfo->DataSize, SetValueInfo->Data);
		}
	}

	*/
	return Status;
}
void countRegList(PHANDLE hkey)
{
	NTSTATUS status;
	KEY_FULL_INFORMATION keyInfo;
	ULONG rLength;
	status = ZwQueryKey(hkey, KeyFullInformation, &keyInfo, sizeof(keyInfo), &rLength);
	if (NT_SUCCESS(status)) {
		DbgPrint("[dmjoo:subkeys] %d\n", keyInfo.SubKeys);
	}
}


NTSTATUS getRegList(PUNICODE_STRING keyName)
{
	NTSTATUS status;
	HANDLE hKey;
	PKEY_FULL_INFORMATION pInfo = NULL;
	ULONG ulInfoSize = 0;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING uKeyName;
	//KEY_BASIC_INFORMATION keyInfo;

	UNREFERENCED_PARAMETER(keyName);

	RtlInitUnicodeString(&uKeyName, L"\\Registry\\Machine\\SOFTWARE\\ODBC");

	InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);


	// 레지스트리 키 오픈
	status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[dmjoo:subkeys]Failed to open registry key. Error code: 0x%X\n", status);
		return status;
	}

	// KeyFullInformation 구조체를 저장할 메모리 할당
	status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &ulInfoSize);
	if (status != STATUS_BUFFER_TOO_SMALL)
	{
		DbgPrint("[dmjoo:subkeys]Failed to query key information size. Error code: 0x%X\n", status);
		ZwClose(hKey);
		return status;
	}

	pInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulInfoSize, 'mytg');
	if (pInfo == NULL)
	{
		DbgPrint("[dmjoo:subkeys]Failed to allocate memory for key information.\n");
		ZwClose(hKey);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// KeyFullInformation 구조체에 정보를 채움
	status = ZwQueryKey(hKey, KeyFullInformation, pInfo, ulInfoSize, &ulInfoSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[dmjoo:subkeys]Failed to query key information. Error code: 0x%X\n", status);
		ExFreePoolWithTag(pInfo, 'mytg');
		ZwClose(hKey);
		return status;
	}
	DbgPrint("[dmjoo:subkeys]%d\n", pInfo->SubKeys);
	// 하위 키 정보 출력
	if (pInfo->SubKeys > 0)
	{
		PKEY_BASIC_INFORMATION pSubInfo = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, pInfo->MaxNameLen, 'mytg');
		if (pSubInfo == NULL)
		{
			DbgPrint("Failed to allocate memory for subkey information.\n");
			ExFreePoolWithTag(pInfo, 'mytg');
			ZwClose(hKey);
		}

		for (ULONG i = 0; i < pInfo->SubKeys; i++)
		{
			status = ZwEnumerateKey(hKey, i, KeyBasicInformation, pSubInfo, pInfo->MaxNameLen, &ulInfoSize);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[dmjoo:subkeys]Failed to enumerate subkey. Error code: 0x%X\n", status);
				continue;
			}

			DbgPrint("[dmjoo]Subkey name: %S\n", &pSubInfo->Name);
		}

		ExFreePoolWithTag(pSubInfo, 'mytg');
		ExFreePoolWithTag(pInfo, 'mytg');
		ZwClose(hKey);
	}

	return status;
}
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdio.h>

#define BUFFER_SIZE 1024

NTSTATUS EnumerateValueNames(PUNICODE_STRING RegistryPath)
{
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hKey;
	//UNICODE_STRING uValueName;
	NTSTATUS status;
	UCHAR buffer[1024];
	PKEY_VALUE_FULL_INFORMATION pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)buffer;
	ULONG length;
	WCHAR sChar;
	int i = 0;
	InitializeObjectAttributes(&objAttr, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_READ, &objAttr);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[dmjoo]ZwOpenKey failed. status = 0x%08x\n", status));
		return status;
	}

	while (TRUE)
	{
		status = ZwEnumerateValueKey(hKey, i++, KeyValueFullInformation, pKeyInfo, sizeof(buffer), &length);

		if (status == STATUS_NO_MORE_ENTRIES)
		{
			KdPrint(("[dmjoo]EnumerateValueNames: no more value entries.\n"));
			break;
		}

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[dmjoo]ZwEnumerateValueKey failed. status = 0x%08x\n", status));
			break;
		}

		// pKeyInfo->NameLength does not include null terminator.
		PWSTR  pValue = (PWSTR)((PUCHAR)pKeyInfo + pKeyInfo->DataOffset);
		pValue[pKeyInfo->DataLength] = L'\0';
		PWSTR pKeyName = (PWSTR)(pKeyInfo->Name);	
		sChar = pKeyName[pKeyInfo->NameLength / sizeof(WCHAR)];
		pKeyName[pKeyInfo->NameLength / sizeof(WCHAR)] = L'\0';
		KdPrint(("[dmjoo]Value name: [%ld] [%S]\n",pKeyInfo->Type,  pKeyName));
		pKeyName[pKeyInfo->NameLength / sizeof(WCHAR)] = sChar;
		KdPrint(("[dmjoo]Value data: [%ld] [%S]\n", pKeyInfo->Type, pValue));
	}

	ZwClose(hKey);
	return status;
}



void getRegValue(PUNICODE_STRING keyName, PUNICODE_STRING valueName)
{
	//UNICODE_STRING keyName;
	//RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Notepad++");

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE keyHandle = NULL;
	NTSTATUS status = ZwOpenKey(&keyHandle, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(status))
	{
		//UNICODE_STRING valueName;
		//RtlInitUnicodeString(&valueName, L"test");

		PVOID data = NULL;
		ULONG dataSize = 0;
		status = ZwQueryValueKey(keyHandle, valueName, KeyValuePartialInformation, NULL, 0, &dataSize);
		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			data = ExAllocatePoolWithTag(NonPagedPool, dataSize, 'MYTG');
			if (data != NULL)
			{
				status = ZwQueryValueKey(keyHandle, valueName, KeyValuePartialInformation, data, dataSize, &dataSize);
				if (NT_SUCCESS(status))
				{
					PKEY_VALUE_PARTIAL_INFORMATION valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)data;
					DbgPrint("[dmjoo]ValueData: %.*S", valueInfo->DataLength, valueInfo->Data);
				}
				ExFreePool(data);
			}
		}

		ZwClose(keyHandle);
	}
}

#include <ntifs.h>


#include <wdm.h>

LONGLONG printMicroTime()
{
	LARGE_INTEGER currentTime;

	// Get the current time
	KeQuerySystemTimePrecise(&currentTime);

	return currentTime.QuadPart;
}

NTSTATUS RegisterRegistryKey(PUNICODE_STRING valueName, PUNICODE_STRING data)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE hKey;
	//UNICODE_STRING valueName;
	//UNICODE_STRING data;
	HANDLE processIdHandle = PsGetCurrentProcessId();
	
	
	UNICODE_STRING g_RegistryPath;// = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\goose\\");
	
	WCHAR processIdString[MAX_KEY_LENGTH] = { 0 };
	
	swprintf_s(processIdString, MAX_KEY_LENGTH, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\goose\\%llu",(ULONGLONG)processIdHandle);
	
	
	RtlInitUnicodeString(&g_RegistryPath, processIdString);
	
	
	DbgPrint("[dmjoo] [%wZ]\n", g_RegistryPath);
	// 레지스트리 키 생성
	InitializeObjectAttributes(&objectAttributes, &g_RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &objectAttributes, 0, NULL, 0, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 레지스트리 값 설정

	//RtlInitUnicodeString(&data, L"C:\\MyDriver.sys");
	status = ZwSetValueKey(hKey, valueName, 0, REG_SZ, data->Buffer, data->Length);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hKey);
		return status;
	}

	// 레지스트리 키 닫기
	ZwClose(hKey);

	return STATUS_SUCCESS;
}

NTSTATUS GetProcessIdString(OUT PUNICODE_STRING ProcessIdString)
{
	HANDLE processIdHandle = PsGetCurrentProcessId();
	WCHAR buffer[10]; // PID는 최대 5자리까지만 가능하므로 10바이트로 충분합니다.
	NTSTATUS status;

	// PID 값을 문자열로 변환합니다.
	status = RtlStringCchPrintfW(buffer, 10, L"%lu", (ULONGLONG)processIdHandle);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// UNICODE_STRING 구조체를 초기화합니다.
	RtlInitUnicodeString(ProcessIdString, buffer);
	DbgPrint("[dmjoo]RegistryPath PID: %wZ\n", ProcessIdString);
	return STATUS_SUCCESS;
}

NTSTATUS BackupRegistryKey(PUNICODE_STRING keyPath,PLARGE_INTEGER  microtime)
{
	OBJECT_ATTRIBUTES keyAttributes;
	OBJECT_ATTRIBUTES backupAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE keyHandle = NULL;
	HANDLE backupHandle = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING backupPath;
	WCHAR buffer[64];
	InitializeObjectAttributes(&keyAttributes, keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateKey(&keyHandle, KEY_READ, &keyAttributes, 0, NULL, REG_OPTION_BACKUP_RESTORE, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create registry key handle, error: %x\n", status);
		return status;
	}

	swprintf_s(buffer, 64, L"\\??\\C:\\users\\goose\\%llu.reg", microtime->QuadPart);
	RtlInitUnicodeString(&backupPath, buffer);

	DbgPrint("[dmjoo:backuppath] %wZ\n", backupPath);

	InitializeObjectAttributes(&backupAttributes, &backupPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateFile(&backupHandle, GENERIC_WRITE | SYNCHRONIZE, &backupAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		ZwClose(keyHandle);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create backup file handle, error: %x\n", status);
		return status;
	}

	status = ZwSaveKey(keyHandle, backupHandle);
	if (!NT_SUCCESS(status))
	{
		ZwClose(keyHandle);
		ZwClose(backupHandle);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to save registry key to backup file, error: %x\n", status);
		return status;
	}

	ZwClose(keyHandle);
	ZwClose(backupHandle);

	return STATUS_SUCCESS;
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

