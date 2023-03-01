#include "stdio.h"
#include <ntifs.h>
#include "regfltr.h"

void getRegValue();
void getRegList(PUNICODE_STRING keyName);
NTSTATUS BackupRegistryKey(PUNICODE_STRING keyPath/*, PUNICODE_STRING backupPath*/);

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

	CallbackCtx = (PCALLBACK_CONTEXT)CallbackContext;
	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	HANDLE pid = PsGetCurrentProcessId();

	if ((ULONGLONG)pid != 5272) return STATUS_SUCCESS;


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
		BackupRegistryKey(RootObjectName);
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

void getRegList(PUNICODE_STRING keyName)
{
	//UNICODE_STRING keyName;
	OBJECT_ATTRIBUTES attributes;
	HANDLE hKey;
	NTSTATUS status;
	//ULONG subKeyCount;
	KEY_FULL_INFORMATION keyInfo;
	ULONG rLength;
	// 백업할 레지스트리 키 이름
	//RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

	// 레지스트리 키 열기
	InitializeObjectAttributes(&attributes, keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &attributes);
	if (!NT_SUCCESS(status)) {
		// 에러 처리
	}

	// 하위 키 수 가져오기
	//status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &subKeyCount);
	//if (!NT_SUCCESS(status)) {
		// 에러 처리
	//}
	status = ZwQueryKey(hKey, KeyFullInformation, &keyInfo, sizeof(keyInfo), &rLength);
	if (!NT_SUCCESS(status)) {
		// 에러 처리
	}

	DbgPrint("[dmjoo:subkeycount] %d : %d : %d\n", keyInfo.SubKeys, rLength, sizeof(keyInfo));
	// 하위 키 수만큼 반복하여 각 하위 키 백업
	for (ULONG i = 0; i < keyInfo.SubKeys; i++) {
		// 하위 키 이름 가져오기
		WCHAR subKeyNameBuffer[256];
		ULONG subKeyNameLength;
		status = ZwEnumerateKey(hKey, i, KeyBasicInformation, subKeyNameBuffer, sizeof(subKeyNameBuffer), &subKeyNameLength);
		if (!NT_SUCCESS(status)) {
			// 에러 처리
			DbgPrint("[dmjoo:subkey] error %d\n", status);
			continue;
		}

		// 하위 키 열기
		OBJECT_ATTRIBUTES subKeyAttributes;
		HANDLE hSubKey;
		UNICODE_STRING subKeyName;
		RtlInitUnicodeString(&subKeyName, subKeyNameBuffer);
		InitializeObjectAttributes(&subKeyAttributes, &subKeyName, OBJ_CASE_INSENSITIVE, hKey, NULL);
		
		DbgPrint("[dmjoo:subkey] %wZ\n", subKeyName);

		status = ZwOpenKey(&hSubKey, KEY_ALL_ACCESS, &subKeyAttributes);
		if (!NT_SUCCESS(status)) {
			// 에러 처리
			continue;
		}

		// 하위 키 백업
		// ...

		// 하위 키 닫기
		ZwClose(hSubKey);
	}


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


NTSTATUS BackupRegistryKey(PUNICODE_STRING keyPath/*, PUNICODE_STRING backupPath*/)
{
	OBJECT_ATTRIBUTES keyAttributes;
	OBJECT_ATTRIBUTES backupAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE keyHandle = NULL;
	HANDLE backupHandle = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING backupPath;

	InitializeObjectAttributes(&keyAttributes, keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateKey(&keyHandle, KEY_READ, &keyAttributes, 0, NULL, REG_OPTION_BACKUP_RESTORE, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create registry key handle, error: %x\n", status);
		return status;
	}

	RtlInitUnicodeString(&backupPath, L"\\??\\C:\\users\\option\\regfile.reg");
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

