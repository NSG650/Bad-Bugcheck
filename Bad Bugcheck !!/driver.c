#include <ntddk.h>
#include <ntstrsafe.h>

CHAR KeBugCheckExOrignalBytes[14] = { 0 };
ULONG_PTR KeBugCheckExAddress;

PVOID ExReallocatePool(POOL_TYPE PoolType, PVOID Old, SIZE_T NumberOfBytes, SIZE_T OldNumberOfBytes, ULONG Tag) {
    PVOID New = ExAllocatePoolZero(PoolType, NumberOfBytes, Tag);
    if (!Old)
        return New;
    RtlCopyMemory(New, Old, OldNumberOfBytes);
    ExFreePool(Old);
    return New;
}

#define STB_IMAGE_IMPLEMENTATION
#define STBI_MALLOC(x) ExAllocatePoolZero(NonPagedPool, x, 'OMAL')
#define STBI_FREE(x) if (x) { ExFreePool(x); }
#define STBI_REALLOC_SIZED(x, y, z)  ExReallocatePool(NonPagedPool, x, z, y, 'OMAL');
#define STBI_NO_THREAD_LOCALS
#define STBI_NO_STDIO
#define STBI_NO_HDR
#define STBI_NO_LINEAR
#define STBI_ASSERT ASSERT

#include "stb_image.h"

extern int _fltused = 0x9875; // taken from "stub.c" in the CRT sources.

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)
#define DELAY_SECOND (DELAY_ONE_MILLISECOND * 1000)

NTKERNELAPI
VOID
InbvAcquireDisplayOwnership(
    VOID
);

BOOLEAN FileRead(PCWSTR path, PVOID buffer, ULONG len, INT offset) {
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&uniName, path);
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE handle;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        KeLowerIrql(PASSIVE_LEVEL);
    }

    status = ZwCreateFile(&handle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    LARGE_INTEGER      byteOffset;

    if (!NT_SUCCESS(status))
        return FALSE;

    byteOffset.LowPart = byteOffset.HighPart = offset;
    status = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, len, &byteOffset, NULL);
    if (!NT_SUCCESS(status))
        return FALSE;

    ZwClose(handle);
    return TRUE;
}

BOOLEAN FileGetInfo(PCWSTR path, PFILE_STANDARD_INFORMATION out) {
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&uniName, path);
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE handle;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        KeLowerIrql(PASSIVE_LEVEL);
    }

    status = ZwCreateFile(&handle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status))
        return FALSE;

    status = ZwQueryInformationFile(handle, &ioStatusBlock, out, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

    if (!NT_SUCCESS(status)) {
        ZwClose(handle);
        return FALSE;
    }

    ZwClose(handle);
    return TRUE;
}

PVOID FileReturnData(PCWSTR Path, PFILE_STANDARD_INFORMATION Out) {
    if (!FileGetInfo(Path, Out))
        return NULL;

    PVOID FileBuffer = ExAllocatePoolZero(NonPagedPool, Out->AllocationSize.QuadPart, 'OAML');

    if (!FileRead(Path, FileBuffer, Out->AllocationSize.QuadPart, 0)) {
        ExFreePool(FileBuffer);
        return NULL;
    }

    return FileBuffer;
}

NTSTATUS Overwrite(PVOID Address, PVOID Data, ULONG Size) {
    PHYSICAL_ADDRESS PhysAddress = MmGetPhysicalAddress(Address);
    PVOID MappedAddress = MmMapIoSpace(PhysAddress, Size, MmNonCached);

    if (MappedAddress == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(MappedAddress, Data, Size);
    MmUnmapIoSpace(MappedAddress, Size);
    return STATUS_SUCCESS;
}

VOID BadAppleEntry(VOID) {
    InbvAcquireDisplayOwnership();

    PHYSICAL_ADDRESS PhysAddr = { 0 };
    FILE_STANDARD_INFORMATION FileInfo = { 0 };
    WCHAR RawFilePath[512] = { 0 };
    LONG32 w, h, n;
    LARGE_INTEGER Delay = { 0 };
    Delay.QuadPart = DELAY_ONE_MICROSECOND * 41;

    PhysAddr.QuadPart = 0xf0000000;
    PVOID Framebuffer = MmMapVideoDisplay(PhysAddr, 0xf7ffffff - 0xf0000000, MmNonCached); // This is only for Microsoft Basic Display Adapter !!!
    // Bad !!!

    memset(Framebuffer, 0x00, 1024 * 768 * 4); // Black out!

    for (SIZE_T i = 0; i < 5259; i++) {
        RtlStringCbPrintfExW(RawFilePath, 512, NULL, NULL, STRSAFE_NO_TRUNCATION, L"\\DosDevices\\C:\\badapple_out\\%d.jpg", i);
        PVOID ImageBuffer = FileReturnData(RawFilePath, &FileInfo);
        if (!ImageBuffer) {
            continue;
        }
        ULONG32* ImageData = (ULONG32*)stbi_load_from_memory(ImageBuffer, FileInfo.AllocationSize.QuadPart, &w, &h, &n, 4);
        if (w != 1024 && h != 768) {
            ExFreePool(ImageBuffer);
            continue;
        }
        RtlCopyMemory(Framebuffer, ImageData, w * h * 4);
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        ExFreePool(ImageBuffer);
        stbi_image_free(ImageData);
    }
}

VOID KeHookedBugCheckEx(ULONG BugCheckCode, ULONG_PTR Code1, ULONG_PTR Code2,
    ULONG_PTR Code3, ULONG_PTR Code4) {
    DbgPrint("[*] KeBugCheckEx was called by Process %ld, thread id %ld\n", PsGetCurrentProcessId(), PsGetCurrentThreadId());
    DbgPrint("[*] KeBugCheckEx(0x%lx, 0x%lx, 0x%lx, 0x%lx)\n", BugCheckCode,
        Code1, Code2, Code3, Code4);
    LARGE_INTEGER Delay;

    Delay.LowPart = 0;
    Delay.HighPart = 0x80000000;

    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}


VOID KeBadCheckEx(ULONG BugCheckCode, ULONG_PTR Code1, ULONG_PTR Code2,
    ULONG_PTR Code3, ULONG_PTR Code4) {

    // We patch to jump to a dummy KeBugCheckEx function incase any other thread calls KeBugCheckEx
    // We don't want to have more than 1 instance of bad apple running

#if defined(_M_X64)
    CHAR Patch[] = {
        0x49, 0xba, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov r10, address
        0x41, 0xff, 0xe2 // jmp r10
    };

    ULONG_PTR KeHookedBugCheckExAddress = (ULONG_PTR)KeHookedBugCheckEx;
    CHAR* KeHookedBugCheckExAddressBytes = (CHAR*)&KeHookedBugCheckExAddress;

    RtlCopyMemory(&Patch[2], KeHookedBugCheckExAddressBytes, sizeof(ULONG_PTR));

    NTSTATUS status = Overwrite((PVOID)KeBugCheckExAddress, (PVOID)Patch, sizeof(Patch));

    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Failed to overwrite KeBugCheckEx\n");
    }

    DbgPrint("[+] Successfully overwrote KeBugCheckEx\n");
#else
    DbgPrint("[!] Unknown architecture");
#endif

    BadAppleEntry();

    // Restore the original KeBugCheckEx function

    status = Overwrite((PVOID)KeBugCheckExAddress, (PVOID)KeBugCheckExOrignalBytes, 14);

    if (!NT_SUCCESS(status))
        DbgPrint("[!] Failed to restore the orignal KeBugCheckEx function\n");
    else
        DbgPrint("[+] Successfully restored the orignal KeBugCheckEx function\n");

    KeBugCheckEx(BugCheckCode, Code1, Code2, Code3, Code4); // Call the original in the end
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    NTSTATUS Status = Overwrite((PVOID)KeBugCheckExAddress, (PVOID)KeBugCheckExOrignalBytes, 14);

    if (Status != STATUS_SUCCESS)
        DbgPrint("[!] Failed to restore the orignal KeBugCheckEx function\n");
    else
        DbgPrint("[+] Successfully restored the orignal KeBugCheckEx function\n");

    DbgPrint("[*] Goodbye Cruel World\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    KeBugCheckExAddress = (ULONG_PTR)KeBugCheckEx;

#if defined(_M_X64)
    CHAR Patch[] = {
        0x49, 0xba, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov r10, address
        0x41, 0xff, 0xe2 // jmp r10
    };

    RtlCopyMemory(KeBugCheckExOrignalBytes, KeBugCheckExAddress, 14);
    ULONG_PTR KeBadBugCheckExAddress = (ULONG_PTR)KeBadCheckEx;
    CHAR* KeBadBugCheckExAddressBytes = (CHAR*)&KeBadBugCheckExAddress;

    RtlCopyMemory(&Patch[2], KeBadBugCheckExAddressBytes, sizeof(ULONG_PTR));

    NTSTATUS Status = Overwrite((PVOID)KeBugCheckExAddress, (PVOID)Patch, sizeof(Patch));

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[!] Failed to overwrite KeBugCheckEx\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    DbgPrint("[+] Successfully overwrote KeBugCheckEx\n");
#else
    DbgPrint("[!] Unknown architecture");
    return STATUS_FAILED_DRIVER_ENTRY;
#endif

    return STATUS_SUCCESS;
}