#include "pch.h"

/*
一旦一个CALLBACK_ENTRY_ITEM已经被填充，
它被传递给ObpInserCallbackByAltitude，这正是它的声音。
如果你不熟悉Altiutde，它只是一个数字值，表示应该调用回调的顺序。
较低的数字称为第一，较高的数字称为last。
当插入回调时，回调根据其高度值插入到链表。中
如果具有相同高度的回调已经在列表中，则不插入新回调，而是ObpInsertCallbackByAltitude返回值STATUS_FLT_INSTANCE_ALTITUDE_COLLISION，指示冲突。
鉴于微软的支持高度达到43万，这是不可能的碰撞将发生在野外的机会。 https://msdn.microsoft.com/en-us/library/windows/hardware/ff549689%28v=vs.85%29.aspx
参考链接:https://douggemhax.wordpress.com/2015/05/27/obregistercallbacks-and-countermeasures/#comments
*/

#define DRIVER_TAG 'xxxx'
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
ULONG ObjectCallbackListOffset = 0;
NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

typedef struct _LDR_DATA
{
    /*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;
    /*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;
    /*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;
    /*0x030*/     VOID*        DllBase;
    /*0x038*/     VOID*        EntryPoint;
    /*0x040*/     ULONG32      SizeOfImage;
    /*0x044*/     UINT8        _PADDING0_[0x4];
    /*0x048*/     struct _UNICODE_STRING FullDllName;
    /*0x058*/     struct _UNICODE_STRING BaseDllName;
    /*0x068*/     ULONG32      Flags;
    /*0x06C*/     UINT16       LoadCount;
    /*0x06E*/     UINT16       TlsIndex;
    union
    {
        /*0x070*/         struct _LIST_ENTRY HashLinks;
        struct
        {
            /*0x070*/             VOID*        SectionPointer;
            /*0x078*/             ULONG32      CheckSum;
            /*0x07C*/             UINT8        _PADDING1_[0x4];
        };
    };
    union
    {
        /*0x080*/         ULONG32      TimeDateStamp;
        /*0x080*/         VOID*        LoadedImports;
    };
    /*0x088*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    /*0x090*/     VOID*        PatchInformation;
    /*0x098*/     struct _LIST_ENTRY ForwarderLinks;
    /*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;
    /*0x0B8*/     struct _LIST_ENTRY StaticLinks;
    /*0x0C8*/     VOID*        ContextInformation;
    /*0x0D0*/     UINT64       OriginalBase;
    /*0x0D8*/     union _LARGE_INTEGER LoadTime;
}LDR_DATA, *PLDR_DATA;

//这里字节对齐要采用默认，不要按1对齐，这样才符合32位和64位结构体
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        struct
        {
            ULONG TimeDateStamp;
        };
        struct
        {
            PVOID LoadedImports;
        };
    };
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _OPERATION_INFO_ENTRY
{
    LIST_ENTRY    ListEntry;
    OB_OPERATION  Operation;
    ULONG         Flags;
    PVOID         Object;
    POBJECT_TYPE  ObjectType;
    ACCESS_MASK   AccessMask;
} OPERATION_INFO_ENTRY, *POPERATION_INFO_ENTRY;

typedef struct _CALL_BACK_INFO
{
    ULONG64 Unknow;
    ULONG64 Unknow1;
    UNICODE_STRING AltitudeString;
    LIST_ENTRY NextEntryItemList; //(callbacklist) 跟上面开头的那个一样 存储下一个callbacklist
    ULONG64 Operations;
    PVOID ObHandle; //存储详细的数据 版本号 POB_OPERATION_REGISTRATION AltitudeString 也就是本身节点CALL_BACK_INFO 注销时也使用这个 注意是指针 //CALL_BACK_INFO
    PVOID ObjectType;
    ULONG64 PreCallbackAddr;
    ULONG64 PostCallbackAddr;
}CALL_BACK_INFO, *PCALL_BACK_INFO;

typedef struct _OB_CALLBACK
{
    LIST_ENTRY	ListEntry;
    ULONG64		Operations;
    PCALL_BACK_INFO		ObHandle;
    ULONG64		ObjTypeAddr;
    ULONG64		PreCall;
    ULONG64		PostCall;
} OB_CALLBACK, *POB_CALLBACK;

LIST_ENTRY  g_OperationListHead;
FAST_MUTEX  g_OperationListLock;
PVOID       g_UpperHandle = NULL;
PVOID       g_LowerHandle = NULL;

OB_PREOP_CALLBACK_STATUS UpperPreCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    POPERATION_INFO_ENTRY NewEntry = NULL;
    PEPROCESS Process = NULL;

    if (PsGetCurrentProcess() == PsInitialSystemProcess)
        return OB_PREOP_SUCCESS;

    if(OperationInformation->ObjectType == PsThreadType)
        return OB_PREOP_SUCCESS;

    Process = PsGetCurrentProcess();

    if (_strnicmp("XiaoBaoBao.exe", PsGetProcessImageFileName(Process), strlen("XiaoBaoBao.exe")))
        return OB_PREOP_SUCCESS;

    NewEntry = (POPERATION_INFO_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(OPERATION_INFO_ENTRY), DRIVER_TAG);

    if (NewEntry)
    {
        NewEntry->Operation = OperationInformation->Operation;
        NewEntry->Flags = OperationInformation->Flags;
        NewEntry->Object = OperationInformation->Object;
        NewEntry->ObjectType = OperationInformation->ObjectType;
        NewEntry->AccessMask = 0x1fffff;//OperationInformation->Parameters->CreateHandleInformation.DesiredAccess; /// Same for duplicate handle
        ExAcquireFastMutex(&g_OperationListLock);
        InsertTailList(&g_OperationListHead, &NewEntry->ListEntry);
        ExReleaseFastMutex(&g_OperationListLock);
    }

    UNREFERENCED_PARAMETER(RegistrationContext);

    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS LowerPreCallback(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
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
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = Entry->AccessMask;
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
// EAC 回调码 327530
// BE 363220
OB_CALLBACK_REGISTRATION UpperCallbackRegistration =
{
    OB_FLT_REGISTRATION_VERSION,
    2,
    RTL_CONSTANT_STRING(L"363235"),//高的
    NULL,
    ObUpperOperationRegistration
};

OB_CALLBACK_REGISTRATION LowerCallcackRegistration =
{
    OB_FLT_REGISTRATION_VERSION,
    2,
    RTL_CONSTANT_STRING(L"363210"),//低的
    NULL,
    ObLowerOperationRegistration
};

void ObRegisterUnload()
{
    if (NULL != g_LowerHandle)
        ObUnRegisterCallbacks(g_LowerHandle);
    if (NULL != g_UpperHandle)
        ObUnRegisterCallbacks(g_UpperHandle);
    while (!IsListEmpty(&g_OperationListHead))
        ExFreePoolWithTag(RemoveHeadList(&g_OperationListHead), DRIVER_TAG);
}

BOOLEAN ObRegisterCallBacksInit(PDRIVER_OBJECT pDriverObject)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PLDR_DATA ldr;

    ldr = (PLDR_DATA)pDriverObject->DriverSection;
    ldr->Flags |= 0x20;

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

Exit:
    if (!NT_SUCCESS(Status))
        ObRegisterUnload();

    return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN GetVersionAndHardCode()
{
    BOOLEAN b = FALSE;
    switch (*NtBuildNumber)
    {
    case 7600:
    case 7601:
    {
        ObjectCallbackListOffset = 0xC0;
        b = TRUE;
        break;
    }
    case 9200:
    {
        ObjectCallbackListOffset = 0xC8;	//OBJECT_TYPE.CallbackList
        b = TRUE;
        break;
    }
    case 9600:
    {
        ObjectCallbackListOffset = 0xC8;	//OBJECT_TYPE.CallbackList
        b = TRUE;
        break;
    }
    default:
        if (*NtBuildNumber > 10000)
        {
            ObjectCallbackListOffset = 0xc8;
            b = TRUE;
        }
        break;
    }
    return b;
}

PVOID GetCallPoint(PVOID pCallPoint)
{
    ULONG dwOffset = 0;
    ULONG_PTR returnAddress = 0;
    LARGE_INTEGER returnAddressTemp = { 0 };
    PUCHAR pFunAddress = NULL;

    if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
        return NULL;

    pFunAddress = pCallPoint;
    // 函数偏移  
    RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 1), sizeof(ULONG));

    // JMP向上跳转  
    if ((dwOffset & 0x10000000) == 0x10000000)
    {
        dwOffset = dwOffset + 5 + pFunAddress;
        returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
        returnAddressTemp.LowPart = dwOffset;
        returnAddress = returnAddressTemp.QuadPart;
        return (PVOID)returnAddress;
    }

    returnAddress = (ULONG_PTR)dwOffset + 5 + pFunAddress;
    return (PVOID)returnAddress;
}

PVOID GetMovPoint(PVOID pCallPoint)
{
    ULONG dwOffset = 0;
    ULONG_PTR returnAddress = 0;
    LARGE_INTEGER returnAddressTemp = { 0 };
    PUCHAR pFunAddress = NULL;

    if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
        return NULL;

    pFunAddress = pCallPoint;
    // 函数偏移  
    RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 3), sizeof(ULONG));

    // JMP向上跳转  
    if ((dwOffset & 0x10000000) == 0x10000000)
    {
        dwOffset = dwOffset + 7 + pFunAddress;
        returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
        returnAddressTemp.LowPart = dwOffset;
        returnAddress = returnAddressTemp.QuadPart;
        return (PVOID)returnAddress;
    }

    returnAddress = (ULONG_PTR)dwOffset + 7 + pFunAddress;
    return (PVOID)returnAddress;
}

PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress, IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, UCHAR SegCode, ULONG AddNum, BOOLEAN ByName)
{
    ULONG dwIndex = 0;
    PUCHAR pFunAddress = NULL;
    ULONG dwCodeNum = 0;

    if (pFeatureCode == NULL)
        return NULL;

    if (FeatureCodeNum >= 15)
        return NULL;

    if (SerSize > 0x1024)
        return NULL;

    if (ByName)
    {
        if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
            return NULL;

        pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName);
        if (pFunAddress == NULL)
            return NULL;
    }
    else
    {
        if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
            return NULL;

        pFunAddress = pStartAddress;
    }

    for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
    {
        __try
        {
            if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] || pFeatureCode[dwCodeNum] == SegCode)
            {
                dwCodeNum++;

                if (dwCodeNum == FeatureCodeNum)
                    return pFunAddress + dwIndex - dwCodeNum + 1 + AddNum;

                continue;
            }

            dwCodeNum = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    return 0;
}

PVOID GetPsLoadedListModule()
{
    /*
    为什么不使用DriverObject去枚举呢 主要是win10这玩意导出了 追随步伐啊 哈哈
    RtlPcToFileHeader
    text:000000014015D6A3 48 8B 0D 86 50 0E 00                          mov     rcx, qword ptr cs:PsLoadedModuleList
    .text:000000014015D6AA 48 85 C9                                      test    rcx, rcx
    .text:000000014015D6AD 74 28                                         jz      short loc_14015D6D7
    .text:000000014015D6AF 48 8D 15 7A 50 0E 00                          lea     rdx, PsLoadedModuleList
    */
    UNICODE_STRING usRtlPcToFileHeader = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
    UNICODE_STRING usPsLoadedModuleList = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    PVOID Point = NULL;
    static PVOID PsLoadedListModule = NULL;
    UCHAR shellcode[11] =
        "\x48\x8b\x0d\x60\x60\x60\x60"
        "\x48\x85\xc9";

    if (PsLoadedListModule)
        return PsLoadedListModule;

    if (*NtBuildNumber > 9600)
    {
        // win10 PsLoadedModuleList导出
        PsLoadedListModule = MmGetSystemRoutineAddress(&usPsLoadedModuleList);
        return PsLoadedListModule;
    }

    Point = GetUndocumentFunctionAddress(&usRtlPcToFileHeader, NULL, shellcode, 10, 0xff, 0x60, 0, TRUE);
    if (Point == NULL || !MmIsAddressValid(Point))
        return NULL;

    Point = GetMovPoint(Point);
    if (Point == NULL || !MmIsAddressValid(Point))
        return NULL;

    PsLoadedListModule = Point;
    return PsLoadedListModule;
}

BOOLEAN ObGetDriverNameByPoint(ULONG_PTR Point, WCHAR* szDriverName)
{
    PLDR_DATA_TABLE_ENTRY Begin = NULL;
    PLIST_ENTRY Head = NULL;
    PLIST_ENTRY Next = NULL;

    Begin = GetPsLoadedListModule();

    if (Begin == NULL)
        return FALSE;

    Head = (PLIST_ENTRY)Begin->InLoadOrderLinks.Flink;
    Next = Head->Flink;

    do
    {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        Next = Next->Flink;

        if ((ULONG_PTR)Entry->DllBase <= Point && Point <= ((ULONG_PTR)Entry->DllBase + Entry->SizeOfImage))
        {
            if (szDriverName == NULL)
                return FALSE;
            RtlZeroMemory(szDriverName, 600);
            RtlCopyMemory(szDriverName, Entry->BaseDllName.Buffer, Entry->BaseDllName.Length);
            return TRUE;
        }

    } while (Next != Head->Flink);

    return FALSE;
}

ULONG EnumObRegisterCallBacks()
{
    ULONG c = 0;
    PLIST_ENTRY CurrEntry = NULL;
    POB_CALLBACK pObCallback;
    ULONG64 ObProcessCallbackListHead = 0;
    ULONG64 ObThreadCallbackListHead = 0;
    WCHAR* szDriverBaseName = NULL;
    szDriverBaseName = ExAllocatePool(NonPagedPool, 600);
    if (szDriverBaseName == NULL)
        return FALSE;

    RtlZeroMemory(szDriverBaseName, 600);

    GetVersionAndHardCode();
    
    ObProcessCallbackListHead = *(ULONG64*)PsProcessType + ObjectCallbackListOffset;
    ObThreadCallbackListHead = *(ULONG64*)PsThreadType + ObjectCallbackListOffset;

    DPRINT("Process:\n");
    CurrEntry = ((PLIST_ENTRY)ObProcessCallbackListHead)->Flink;

    if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
    {
        ExFreePool(szDriverBaseName);
        return 0;
    }

    do
    {
        pObCallback = (POB_CALLBACK)CurrEntry;
        if (pObCallback->ObHandle != 0)
        {
            DPRINT("ObHandle: %p\n", pObCallback->ObHandle);
            DPRINT("Index: %wZ\n", &pObCallback->ObHandle->AltitudeString);
            DPRINT("PreCall: %p\n", pObCallback->PreCall);
            DPRINT("PostCall: %p\n", pObCallback->PostCall);
            if (ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
                DPRINT("DriverName: %S\n", szDriverBaseName);
            c++;
        }

        CurrEntry = CurrEntry->Flink;

    } while (CurrEntry != (PLIST_ENTRY)ObProcessCallbackListHead);

    DPRINT("Thread:\n");
    CurrEntry = ((PLIST_ENTRY)ObThreadCallbackListHead)->Flink;
    if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
    {
        ExFreePool(szDriverBaseName);
        return c;
    }

    do
    {
        pObCallback = (POB_CALLBACK)CurrEntry;
        if (pObCallback->ObHandle != 0)
        {
            DPRINT("ObHandle: %p\n", pObCallback->ObHandle);
            DPRINT("Index: %wZ\n", &pObCallback->ObHandle->AltitudeString);
            DPRINT("PreCall: %p\n", pObCallback->PreCall);
            DPRINT("PostCall: %p\n", pObCallback->PostCall);
            if(ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
                DPRINT("DriverName: %S\n", szDriverBaseName);
            c++;
        }

        CurrEntry = CurrEntry->Flink;

    } while (CurrEntry != (PLIST_ENTRY)ObThreadCallbackListHead);

    DPRINT("ObCallback count: %ld\n", c);

    ExFreePool(szDriverBaseName);
    return c;
}


BOOLEAN ObGetCallBacksAltitude(WCHAR* szDriverName, PUNICODE_STRING usAltitudeString, BOOLEAN bGetProcess)
{
    BOOLEAN bRet = FALSE;
    PLIST_ENTRY CurrEntry = NULL;
    POB_CALLBACK pObCallback;
    ULONG_PTR ObCallbackListHead = 0;
    WCHAR* szDriverBaseName = NULL;

    GetVersionAndHardCode();

    if (bGetProcess)
        ObCallbackListHead = *(ULONG_PTR*)PsProcessType + ObjectCallbackListOffset;
    else
        ObCallbackListHead = *(ULONG_PTR*)PsThreadType + ObjectCallbackListOffset;

    CurrEntry = ((PLIST_ENTRY)ObCallbackListHead)->Flink;

    if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
        return bRet;

    if (szDriverName == NULL || usAltitudeString == NULL || usAltitudeString->Buffer == NULL)
        return FALSE;

    szDriverBaseName = ExAllocatePool(NonPagedPool, 600);

    if (szDriverBaseName == NULL)
        return FALSE;

    RtlZeroMemory(szDriverBaseName, 600);
    do
    {
        pObCallback = (POB_CALLBACK)CurrEntry;
        if (pObCallback->ObHandle != 0)
        {
            DPRINT("ObHandle: %p\n", pObCallback->ObHandle);
            DPRINT("Index: %wZ\n", &pObCallback->ObHandle->AltitudeString);
            DPRINT("PreCall: %p\n", pObCallback->PreCall);
            DPRINT("PostCall: %p\n", pObCallback->PostCall);
            if (!ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
                break;

            DPRINT("DriverName: %S\n", szDriverBaseName);
            if (!_wcsnicmp(szDriverBaseName, szDriverName, wcslen(szDriverName) * 2))
            {
                bRet = TRUE;
                RtlCopyMemory(usAltitudeString->Buffer, pObCallback->ObHandle->AltitudeString.Buffer, pObCallback->ObHandle->AltitudeString.Length);
                usAltitudeString->Length = pObCallback->ObHandle->AltitudeString.Length;
                usAltitudeString->MaximumLength = 600;
                break;
            }
        }
        CurrEntry = CurrEntry->Flink;
    } while (CurrEntry != (PLIST_ENTRY)ObCallbackListHead);

    ExFreePool(szDriverBaseName);
    return bRet;
}