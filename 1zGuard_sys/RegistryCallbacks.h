#pragma once
#include "Common.h"
#include "RuleManager.h"
#include "SharedMemory.h"

extern "C" NTSTATUS InitializeRegistryCallback(_In_ PDRIVER_OBJECT DriverObject);
extern "C" VOID UninitializeRegistryCallback();
