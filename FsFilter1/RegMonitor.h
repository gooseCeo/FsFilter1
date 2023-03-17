#include "stdio.h"
#include <ntifs.h>
#include "regfltr.h"
#include <ntddk.h>
#include <tchar.h>


#define MAX_KEY_LENGTH 256
int existKey(PUNICODE_STRING searchObject);
NTSTATUS EnumerateRegistryKeys(PUNICODE_STRING KeyPath);
UNICODE_STRING ParseRegistryKey(PUNICODE_STRING registryKey);
NTSTATUS RegisterRegistryKey(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING data);
NTSTATUS GetProcessIdString(OUT PUNICODE_STRING ProcessIdString);
void keepRegistry(PUNICODE_STRING ObjectName);
void getRegValue();
void getRegList(PUNICODE_STRING keyName);
NTSTATUS BackupRegistryKey(PUNICODE_STRING keyPath, PUNICODE_STRING microtime);
extern int getProcName(PEPROCESS pProcess, PCHAR procName);
NTSTATUS CreateDirectory(PUNICODE_STRING DirectoryName);
NTSTATUS CopyRegistryKey(PUNICODE_STRING srcKeyName, PUNICODE_STRING dstKeyName);

typedef struct _GLOBAL_CONTEXT {
	PDRIVER_OBJECT DriverObject;
	UNICODE_STRING Altitude;
	LARGE_INTEGER Cookie;
} GLOBAL_CONTEXT, * PGLOBAL_CONTEXT;

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

	UNICODE_STRING keyName1;
	UNICODE_STRING keyName2;

	CallbackCtx = (PCALLBACK_CONTEXT)CallbackContext;
	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	HANDLE pid = PsGetCurrentProcessId();

	if ((ULONGLONG)pid != 7356) return STATUS_SUCCESS;


	if (Argument2 == NULL) {

		//
		// This should never happen but the sal annotation on the callback 
		// function marks Argument 2 as opt and is looser than what 
		// it actually is.
		//

		return STATUS_SUCCESS;
	}

	//InfoPrint("\t[dmjoo]%d Callback: callbackmode-%d, [%d]NotifyClass-%S.", pid, CallbackCtx->CallbackMode, NotifyClass, GetNotifyClassString(NotifyClass));



	if (RegNtRenameKey == NotifyClass)
	{

		PREG_RENAME_KEY_INFORMATION RegInformation = (PREG_RENAME_KEY_INFORMATION)Argument2;
		//DbgPrint("[ dmjoo start] %d %s\n", NotifyClass, RegInformation->CompleteName->Buffer);
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:rename] %wZ -> %wZ\n", RootObjectName, RegInformation->NewName);
			//getRegList(RootObjectName);
			RtlInitUnicodeString(&keyName1, L"\\Registry\\User\\SOFTWARE\\goose");
			RtlInitUnicodeString(&keyName2, L"\\REGISTRY\\USER\\S - 1 - 5 - 21 - 734880807 - 2553592052 - 4167930440 - 1001\\SOFTWARE\\goose2");

			//EnumerateRegistryKeys(RootObjectName);

			CopyRegistryKey(RootObjectName, &keyName2);
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

		if (existKey(RootObjectName) < 0) keepRegistry(RootObjectName);

	}
	else if (RegNtDeleteValueKey == NotifyClass) {
		PREG_DELETE_VALUE_KEY_INFORMATION RegInformation = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			DbgPrint("[dmjoo:deleteValueKey] %wZ %wZ\n", RootObjectName, RegInformation->ValueName);
		}
		//getRegValue(RootObjectName, RegInformation->ValueName);

		if (existKey(RootObjectName) < 0) keepRegistry(RootObjectName);
	}

	else if (RegNtSetValueKey == NotifyClass) {
		PREG_SET_VALUE_KEY_INFORMATION RegInformation = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(Status = CmCallbackGetKeyObjectID(&g_GlobalContext.Cookie, RegInformation->Object, &RootObjectID, &RootObjectName)))
		{
			//DbgPrint("[dmjoo:SetValueKey] %wZ [%wZ]\n", RootObjectName, RegInformation->ValueName);
			//DbgPrint("[dmjoo:SetValueKey] %wZ[%wZ]\n", RegInformation->ValueName);
			//if ( RegInformation->DataSize > 0 ) DbgPrint("[dmjoo:SetValueKey_Data] [%d:%d:%S]\n", RegInformation->Type, RegInformation->DataSize, RegInformation->Data);

			//getRegValue(RootObjectName, RegInformation->ValueName);

			if (existKey(RootObjectName) < 0) keepRegistry(RootObjectName);
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

int existKey(PUNICODE_STRING searchObject)
{
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hKey;
	//UNICODE_STRING uValueName;
	NTSTATUS status;
	UCHAR buffer[1024];
	PKEY_VALUE_FULL_INFORMATION pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)buffer;
	ULONG length;
	//WCHAR sChar;
	HANDLE pid = PsGetCurrentProcessId();
	CHAR procName[16];
	UNICODE_STRING g_RegistryPath;// = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\goose\\");
	WCHAR processIdString[MAX_KEY_LENGTH] = { 0 };
	swprintf_s(processIdString, MAX_KEY_LENGTH, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\goose\\%llu", (ULONGLONG)pid);
	RtlInitUnicodeString(&g_RegistryPath, processIdString);
	//UNICODE_STRING valueData;

	int i = 0;
	InitializeObjectAttributes(&objAttr, &g_RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_READ, &objAttr);

	if (!NT_SUCCESS(status))
	{
		//KdPrint(("[dmjoo]ZwOpenKey failed. status = 0x%08x\n", status));
		KdPrint(("[dmjoo] 백업\n"));
		return -1;
	}

	while (TRUE)
	{
		status = ZwEnumerateValueKey(hKey, i++, KeyValueFullInformation, pKeyInfo, sizeof(buffer), &length);

		if (status == STATUS_NO_MORE_ENTRIES)
		{
			//KdPrint(("[dmjoo]EnumerateValueNames: no more value entries.\n"));
			break;
		}

		if (!NT_SUCCESS(status))
		{
			//KdPrint(("[dmjoo]ZwEnumerateValueKey failed. status = 0x%08x\n", status));
			break;
		}

		// pKeyInfo->NameLength does not include null terminator.
		PWSTR  pValue = (PWSTR)((PUCHAR)pKeyInfo + pKeyInfo->DataOffset);
		/*
		pValue[pKeyInfo->DataLength] = L'\0';
		PWSTR pKeyName = (PWSTR)(pKeyInfo->Name);
		sChar = pKeyName[pKeyInfo->NameLength / sizeof(WCHAR)];
		pKeyName[pKeyInfo->NameLength / sizeof(WCHAR)] = L'\0';
		KdPrint(("[dmjoo]Value name: [%ld] [%S]\n", pKeyInfo->Type, pKeyName));
		pKeyName[pKeyInfo->NameLength / sizeof(WCHAR)] = sChar;
		KdPrint(("[dmjoo]Value data: [%ld] [%S]\n", pKeyInfo->Type, pValue));
		//KdPrint(("[dmjoo] searchoBJECT[%d] valueData[%d] \n", searchObject->Length, pKeyInfo->DataLength));
		RtlInitUnicodeString(&valueData,pValue);
		*/
		// If lengths are not equal, strings are not equal
		if (searchObject->Length != pKeyInfo->DataLength)
		{
			//KdPrint(("[dmjoo] searchoBJECT[%d] valueData[%d] \n", searchObject->Length, pKeyInfo->DataLength));
			continue;
		}

		// Compare the two strings
		//int cmpResult = RtlCompareUnicodeString(searchObject, &valueData, TRUE);
		int cmpResult = wcsncmp(pValue, searchObject->Buffer, (pKeyInfo->DataLength) / sizeof(WCHAR));
		// If the result is zero, the strings are equal
		if (cmpResult == 0)
		{
			//KdPrint(("[dmjoo] 일치\n"));
			ZwClose(hKey);
			return 0;
		}
		else
		{
			//KdPrint(("[dmjoo][%S] [%S]\n", searchObject->Buffer, pValue));
		}
	}

	ZwClose(hKey);
	KdPrint(("[dmjoo] 백업\n"));
	getProcName(PsGetCurrentProcess(), procName);
	return -1;
}

void keepRegistry(PUNICODE_STRING ObjectName)
{
	WCHAR microtime[20] = { 0 };
	LARGE_INTEGER currentTime;
	UNICODE_STRING backupPath;
	UNICODE_STRING backupfolder;
	WCHAR buffer[64];
	WCHAR buffer2[64];

	UNICODE_STRING valueName;
	HANDLE pid = PsGetCurrentProcessId();
	//NTSTATUS status = STATUS_SUCCESS;

	// Get the current time
	KeQuerySystemTimePrecise(&currentTime);
	DbgPrint("[dmjoo:time] %llu\n", currentTime.QuadPart);
	swprintf_s(microtime, 20, L"%llu", currentTime.QuadPart);

	UNICODE_STRING g_RegistryPath;// = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\goose\\");

	WCHAR processIdString[MAX_KEY_LENGTH] = { 0 };

	swprintf_s(processIdString, MAX_KEY_LENGTH, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\goose\\%llu", (ULONGLONG)pid);
	RtlInitUnicodeString(&g_RegistryPath, processIdString);
	DbgPrint("[dmjoo] [%wZ]\n", g_RegistryPath);
	RtlInitUnicodeString(&valueName, microtime);
	RegisterRegistryKey(&g_RegistryPath, &valueName, ObjectName);


	swprintf_s(buffer2, 64, L"\\??\\C:\\users\\goose\\%llu", (ULONGLONG)pid);
	swprintf_s(buffer, 64, L"\\??\\C:\\users\\goose\\%llu\\%llu.reg", (ULONGLONG)pid, currentTime.QuadPart);
	RtlInitUnicodeString(&backupfolder, buffer2);
	RtlInitUnicodeString(&backupPath, buffer);
	DbgPrint("[dmjoo:backupfolder] %wZ\n", backupfolder);
	DbgPrint("[dmjoo:backuppath] %wZ\n", backupPath);

	/*
	HANDLE handle;
	OBJECT_ATTRIBUTES objAttr;
	// 객체 속성 초기화
	InitializeObjectAttributes(&objAttr, &backupfolder, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// 디렉토리 생성
	IO_STATUS_BLOCK ioStatusBlock;
	status = NtCreateFile(&handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_DIRECTORY, 0, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	// 에러 처리
	if (!NT_SUCCESS(status)) {
		DbgPrint("[dmjoo:folder error] %wZ [0x%X]\n", backupfolder, status);
	}
	else {
		// 핸들 닫기
		ZwClose(handle);
	}
	*/
	CreateDirectory(&backupfolder);

	BackupRegistryKey(ObjectName, &backupPath);
}

void getRegList(PUNICODE_STRING keyName)
{
	OBJECT_ATTRIBUTES attributes;
	HANDLE hKey;
	NTSTATUS status;
	//ULONG subKeyCount;
	KEY_FULL_INFORMATION keyInfo;
	ULONG rLength;
	// 백업할 레지스트리 키 이름
	UNICODE_STRING keyName1;
	//RtlInitUnicodeString(&keyName1, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
	RtlInitUnicodeString(&keyName1, L"\\Registry\\Machine\\SOFTWARE\\Intel");

	UNREFERENCED_PARAMETER(keyName);
	// 레지스트리 키 열기
	InitializeObjectAttributes(&attributes, &keyName1, OBJ_CASE_INSENSITIVE, NULL, NULL);
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

	DbgPrint("[dmjoo:subkeycount] %ld : %ld : %lld\n", keyInfo.SubKeys, rLength, sizeof(keyInfo));
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
		DbgPrint("[dmjoo:subkey] %s\n", subKeyNameBuffer);
		// 하위 키 열기
		OBJECT_ATTRIBUTES subKeyAttributes;
		HANDLE hSubKey;
		UNICODE_STRING subKeyName;
		RtlInitUnicodeString(&subKeyName, subKeyNameBuffer);
		InitializeObjectAttributes(&subKeyAttributes, &subKeyName, OBJ_CASE_INSENSITIVE, hKey, NULL);


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


NTSTATUS EnumerateRegistryKeys(PUNICODE_STRING KeyPath)
{
	HANDLE hKey;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING subKeyName;
	ULONG index = 0;
	ULONG bufferSize = 0;
	PVOID buffer = NULL;
	PKEY_BASIC_INFORMATION keyBasicInfo;

	// 레지스트리 키 열기
	InitializeObjectAttributes(&objectAttributes, KeyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[dmjoo:subkeyname] error\n");
		return status;
	}

	// 하위 키 열거하기
	do
	{
		status = ZwEnumerateKey(hKey, index, KeyBasicInformation, buffer, bufferSize, &bufferSize);
		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			buffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'myTg');
			if (!buffer)
			{
				ZwClose(hKey);
				return STATUS_INSUFFICIENT_RESOURCES;
			}
		}
		index++;
	} while (status == STATUS_BUFFER_TOO_SMALL);

	if (NT_SUCCESS(status))
	{
		// 열거된 키 출력하기
		keyBasicInfo = (PKEY_BASIC_INFORMATION)buffer;
		while (keyBasicInfo->NameLength > 0)
		{
			RtlUnicodeStringInit(&subKeyName, keyBasicInfo->Name);
			DbgPrint("[dmjoo:subkeyname]%wZ\n", &subKeyName);

			keyBasicInfo = (PKEY_BASIC_INFORMATION)(((PUCHAR)keyBasicInfo) + keyBasicInfo->NameLength + sizeof(KEY_BASIC_INFORMATION));
		}
	}

	if (buffer)
	{
		ExFreePoolWithTag(buffer, 'myTg');
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

NTSTATUS RegisterRegistryKey(PUNICODE_STRING key, PUNICODE_STRING valueName, PUNICODE_STRING data)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE hKey;
	//UNICODE_STRING valueName;
	//UNICODE_STRING data;

	// 레지스트리 키 생성
	InitializeObjectAttributes(&objectAttributes, key, OBJ_CASE_INSENSITIVE, NULL, NULL);
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

NTSTATUS BackupRegistryKey(PUNICODE_STRING keyPath, PUNICODE_STRING backupPath)
{
	OBJECT_ATTRIBUTES keyAttributes;
	OBJECT_ATTRIBUTES backupAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE keyHandle = NULL;
	HANDLE backupHandle = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	InitializeObjectAttributes(&keyAttributes, keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateKey(&keyHandle, KEY_READ, &keyAttributes, 0, NULL, REG_OPTION_BACKUP_RESTORE, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create registry key handle, error: %x\n", status);
		return status;
	}

	InitializeObjectAttributes(&backupAttributes, backupPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
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
	}
	else {
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
	}
	else {
		DbgPrint("[ RegMonitor ] [ SUCCESS ] CmUnRegisterCallback Success\n");
	}
	return STATUS_SUCCESS;
}

// 디렉토리 생성 함수
NTSTATUS CreateDirectory(PUNICODE_STRING DirectoryName)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE DirectoryHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status;

	InitializeObjectAttributes(&ObjectAttributes, DirectoryName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(&DirectoryHandle, FILE_GENERIC_WRITE,
		&ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
		0, FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0);

	if (NT_SUCCESS(Status))
	{
		ZwClose(DirectoryHandle);
	}
	else {
		DbgPrint("[dmjoo:createdirectory error] 0x%X\n", Status);
	}

	return Status;
}

// 디렉토리 생성 함수
NTSTATUS fltCreateDirectory(PUNICODE_STRING DirectoryName, PFLT_FILTER Filter)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE DirectoryHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status;

	InitializeObjectAttributes(&ObjectAttributes, DirectoryName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	// FltCreateFile 함수를 사용하여 디렉토리 생성
	Status = FltCreateFile(Filter, NULL, &DirectoryHandle, FILE_GENERIC_WRITE,
		&ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
		0, FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

	if (NT_SUCCESS(Status))
	{
		FltClose(DirectoryHandle);
	}

	return Status;
}
NTSTATUS CopyRegistryKey(PUNICODE_STRING srcKeyName, PUNICODE_STRING dstKeyName)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES srcObjAttr = { 0 };
	OBJECT_ATTRIBUTES dstObjAttr = { 0 };
	HANDLE srcKeyHandle = NULL;
	HANDLE dstKeyHandle = NULL;
	ULONG index = 0;
	ULONG length = 0;
	PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
	PKEY_BASIC_INFORMATION basicInfo = NULL;

	// 1. 원본 키 핸들 얻기
	InitializeObjectAttributes(&srcObjAttr, srcKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&srcKeyHandle, KEY_READ, &srcObjAttr);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[ dmjoo:copyError ] 1. 원본 키 핸들 얻기\n");
		goto Cleanup;
	}

	// 2. 대상 키 생성
	InitializeObjectAttributes(&dstObjAttr, dstKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateKey(&dstKeyHandle, KEY_ALL_ACCESS, &dstObjAttr, 0, NULL, 0, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("[ dmjoo:copyError ] 2. 대상 키 생성\n");
		goto Cleanup;
	}

	// 3. 값 복사
	while (1)
	{
		status = ZwEnumerateValueKey(srcKeyHandle, index++, KeyValueFullInformation, NULL, 0, &length);

		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			valueInfo = ExAllocatePoolWithTag(NonPagedPool, length, 'RegV');
			if (valueInfo == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto Cleanup;
			}

			status = ZwEnumerateValueKey(srcKeyHandle, index - 1, KeyValueFullInformation, valueInfo, length, &length);

			if (!NT_SUCCESS(status))
			{
				ExFreePoolWithTag(valueInfo, 'RegV');
				goto Cleanup;
			}

			status = ZwSetValueKey(dstKeyHandle, (PUNICODE_STRING)&valueInfo->Name, 0, valueInfo->Type, (PVOID)((PUCHAR)valueInfo + valueInfo->DataOffset), valueInfo->DataLength);

			if (!NT_SUCCESS(status))
			{

				ExFreePoolWithTag(valueInfo, 'RegV');
			}
			else if (status == STATUS_NO_MORE_ENTRIES)
			{
				status = STATUS_SUCCESS;
				break;
			}
			else
			{
				goto Cleanup;
			}
		}

		// 4. 하위 키 복사
		index = 0;

		while (1)
		{
			status = ZwEnumerateKey(srcKeyHandle, index++, KeyBasicInformation, NULL, 0, &length);

			if (status == STATUS_BUFFER_TOO_SMALL)
			{
				basicInfo = ExAllocatePoolWithTag(NonPagedPool, length, 'RegB');

				if (basicInfo == NULL)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					goto Cleanup;
				}

				status = ZwEnumerateKey(srcKeyHandle, index - 1, KeyBasicInformation, basicInfo, length, &length);

				if (!NT_SUCCESS(status))
				{
					ExFreePoolWithTag(basicInfo, 'RegB');
					goto Cleanup;
				}

				UNICODE_STRING subKeyName = { 0 };
				subKeyName.Length = (USHORT)basicInfo->NameLength;
				subKeyName.MaximumLength = subKeyName.Length;
				subKeyName.Buffer = basicInfo->Name;

				UNICODE_STRING subKeyDstName = { 0 };
				subKeyDstName.Length = subKeyName.Length;
				subKeyDstName.MaximumLength = subKeyName.MaximumLength;
				subKeyDstName.Buffer = ExAllocatePoolWithTag(NonPagedPool, subKeyName.MaximumLength, 'RegN');

				if (subKeyDstName.Buffer == NULL)
				{
					ExFreePoolWithTag(basicInfo, 'RegB');
					status = STATUS_INSUFFICIENT_RESOURCES;
					goto Cleanup;
				}

				RtlCopyUnicodeString(&subKeyDstName, &subKeyName);

				status = CopyRegistryKey(&subKeyName, &subKeyDstName);

				if (!NT_SUCCESS(status))
				{
					ExFreePoolWithTag(basicInfo, 'RegB');
					ExFreePoolWithTag(subKeyDstName.Buffer, 'RegN');
					goto Cleanup;
				}

				ExFreePoolWithTag(basicInfo, 'RegB');
				ExFreePoolWithTag(subKeyDstName.Buffer, 'RegN');
			}
			else if (status == STATUS_NO_MORE_ENTRIES)
			{
				status = STATUS_SUCCESS;
				break;
			}
			else
			{
				goto Cleanup;
			}
		}

	}
Cleanup:
	if (srcKeyHandle != NULL)
	{
		ZwClose(srcKeyHandle);
	}

	if (dstKeyHandle != NULL)
	{
		ZwClose(dstKeyHandle);
	}
	return status;
}