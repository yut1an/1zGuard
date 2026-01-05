#pragma once

#include <fltKernel.h>

#include "Common.h"
#include "RuleManager.h"
#include "SharedMemory.h"

extern "C" NTSTATUS InitializeMiniFilter(_In_ PDRIVER_OBJECT DriverObject);
extern "C" VOID UninitializeMiniFilter();
