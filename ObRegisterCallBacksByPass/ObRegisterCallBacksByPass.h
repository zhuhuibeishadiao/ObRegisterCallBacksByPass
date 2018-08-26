#pragma once

ULONG EnumObRegisterCallBacks();

BOOLEAN ObRegisterCallBacksInit(PDRIVER_OBJECT pDriverObject);

BOOLEAN ObGetCallBacksAltitude(WCHAR* szDriverName, PUNICODE_STRING usAltitudeString, BOOLEAN bGetProcess);

void ObRegisterUnload();

