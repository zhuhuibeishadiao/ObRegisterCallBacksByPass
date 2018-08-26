#pragma once
#define DRIVER_TAG 'xxxx'

typedef struct _OPERATION_INFO_ENTRY
{
	LIST_ENTRY    ListEntry;
	OB_OPERATION  Operation;
	ULONG         Flags;
	PVOID         Object;
	POBJECT_TYPE  ObjectType;
	ACCESS_MASK   AccessMask;
} OPERATION_INFO_ENTRY, *POPERATION_INFO_ENTRY;

LIST_ENTRY  g_OperationListHead;
FAST_MUTEX  g_OperationListLock;
PVOID       g_UpperHandle = NULL;
PVOID       g_LowerHandle = NULL;

PCHAR GetProcessNameByProcessId(HANDLE ProcessId)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PEPROCESS ProcessObj = NULL;
	PCHAR string = NULL;
	st = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
	if (NT_SUCCESS(st))
	{
		string = (PCHAR)PsGetProcessImageFileName(ProcessObj);
		ObfDereferenceObject(ProcessObj);
	}
	return string;
}

OB_PREOP_CALLBACK_STATUS UpperPreCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	// 进入XignCode3回调前保存一下原来需要的权限
	char szCurrName[16] = { 0 };
	strcpy(szCurrName, GetProcessNameByProcessId(PsGetCurrentProcessId()));

	if (!_strnicmp("Callme.exe", szCurrName, strlen("Calllme.exe")))
	{
		POPERATION_INFO_ENTRY NewEntry = (POPERATION_INFO_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(OPERATION_INFO_ENTRY), DRIVER_TAG);
		if (NewEntry)
		{
			NewEntry->Operation = OperationInformation->Operation;
			NewEntry->Flags = OperationInformation->Flags;
			NewEntry->Object = OperationInformation->Object;
			NewEntry->ObjectType = OperationInformation->ObjectType;
			NewEntry->AccessMask = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess; /// Same for duplicate handle
			ExAcquireFastMutex(&g_OperationListLock);
			InsertTailList(&g_OperationListHead, &NewEntry->ListEntry);
			ExReleaseFastMutex(&g_OperationListLock);
		}
	}
	UNREFERENCED_PARAMETER(RegistrationContext);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS LowerPreCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	// 到这里,XignCode3的处理完成了,抹去了部分权限,这里恢复回来
	PLIST_ENTRY ListEntry;
	UNREFERENCED_PARAMETER(RegistrationContext);

	ExAcquireFastMutex(&g_OperationListLock);
	for (ListEntry = g_OperationListHead.Flink; ListEntry != &g_OperationListHead; ListEntry = ListEntry->Flink)
	{
		POPERATION_INFO_ENTRY Entry = (POPERATION_INFO_ENTRY)ListEntry;
		if (Entry->Operation == OperationInformation->Operation &&
			Entry->Flags == OperationInformation->Flags &&
			Entry->Object == OperationInformation->Object &&
			Entry->ObjectType == OperationInformation->ObjectType)
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = Entry->AccessMask;
			RemoveEntryList(&Entry->ListEntry);
			ExFreePoolWithTag(Entry, DRIVER_TAG);
			goto Release;

		}
	}
Release:
	ExReleaseFastMutex(&g_OperationListLock);

	return OB_PREOP_SUCCESS;
}

OB_OPERATION_REGISTRATION ObUpperOperationRegistration[] =
{
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, UpperPreCallback, NULL },
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, UpperPreCallback, NULL },
};

OB_OPERATION_REGISTRATION ObLowerOperationRegistration[] =
{
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, LowerPreCallback, NULL },
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, LowerPreCallback, NULL },
};

// XignCode3 回调码：380800
OB_CALLBACK_REGISTRATION UpperCallbackRegistration =
{
	OB_FLT_REGISTRATION_VERSION,
	2,
	RTL_CONSTANT_STRING(L"380804"),
	NULL,
	ObUpperOperationRegistration
};

OB_CALLBACK_REGISTRATION LowerCallcackRegistration =
{
	OB_FLT_REGISTRATION_VERSION,
	2,
	RTL_CONSTANT_STRING(L"380795"),
	NULL,
	ObLowerOperationRegistration
};

VOID UnloadObCallByPass()
{
	static BOOLEAN bUnloaded = FALSE;

	if (bUnloaded)
		return;
	
	if (NULL != g_LowerHandle)
		ObUnRegisterCallbacks(g_LowerHandle);
	if (NULL != g_UpperHandle)
		ObUnRegisterCallbacks(g_UpperHandle);
	while (!IsListEmpty(&g_OperationListHead))
		ExFreePoolWithTag(RemoveHeadList(&g_OperationListHead), DRIVER_TAG);

	bUnloaded = TRUE;
}

NTSTATUS LoadObCallByPass()
{
	NTSTATUS  Status = STATUS_UNSUCCESSFUL;
	InitializeListHead(&g_OperationListHead);
	ExInitializeFastMutex(&g_OperationListLock);

	ObUpperOperationRegistration[0].ObjectType = PsProcessType;
	//新添加的
	ObUpperOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	ObUpperOperationRegistration[1].ObjectType = PsThreadType;
	//新添加的
	ObUpperOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	Status = ObRegisterCallbacks(&UpperCallbackRegistration, &g_UpperHandle);
	if (!NT_SUCCESS(Status))
	{
		g_UpperHandle = NULL;
		goto Exit;
	}

	ObLowerOperationRegistration[0].ObjectType = PsProcessType;
	//新添加的
	ObLowerOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	ObLowerOperationRegistration[1].ObjectType = PsThreadType;
	//新添加的
	ObLowerOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	Status = ObRegisterCallbacks(&LowerCallcackRegistration, &g_LowerHandle);
	if (!NT_SUCCESS(Status))
	{
		g_LowerHandle = NULL;
		goto Exit;
	}
	
	DbgPrint("Load ObCallByPass Success !\n");
	return STATUS_SUCCESS;
Exit:
	DbgPrint("ObCallByPass faild ! code :0x%x\n", Status);
	return Status;
}



