#include "pch.h"

void OnUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    //EnumObRegisterCallBacks();
    ObRegisterUnload();
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS  Status = STATUS_SUCCESS;
    DriverObject->DriverUnload = OnUnload;

    
    ObRegisterCallBacksInit(DriverObject);
    return Status;
}