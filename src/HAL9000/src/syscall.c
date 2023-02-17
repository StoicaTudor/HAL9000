#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread_internal.h"
#include "vmm.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {

        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;

        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
                );
            break;

        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)pSyscallParameters[0]);
            break;

        case SyscallIdThreadGetName:
            status = SyscallThreadGetName(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1]
                );
            break;

        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid(
                (UM_HANDLE)pSyscallParameters[0],
                (TID *)pSyscallParameters[1]
                );
            break;
            
        case SyscallIdGetTotalThreadNo:
            status = SyscallGetTotalThreadNo(
                (QWORD*)pSyscallParameters[0]
                );
            break;
            
        case SyscallIdGetThreadUmStackAddress:
            status = SyscallGetThreadUmStackAddress(
                (PVOID*)pSyscallParameters[0]
                );
            break;

        case SyscallIdGetThreadUmStackSize:
            status = SyscallGetThreadUmStackSize(
                (QWORD*)pSyscallParameters[0]
                );
            break;

        case SyscallIdGetThreadUmEntryPoint:
            status = SyscallGetThreadUmEntryPoint(
                (PVOID*)pSyscallParameters[0]
                );
            break;

        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls

STATUS
SyscallFileWrite(
    IN UM_HANDLE FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID Buffer,
    IN QWORD BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    STATUS status;

    // ne trebuie drepturi de read pt a citi din buffer
    status = MmuIsBufferValid(
        Buffer,
        BytesToWrite,
        PAGE_RIGHTS_READ,
        GetCurrentProcess()
    );

    status = MmuIsBufferValid(
        BytesWritten,
        sizeof(BytesWritten),
        PAGE_RIGHTS_READ,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for ", status);
        return status;
    }

    if(FileHandle == UM_FILE_HANDLE_STDOUT)
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);

    *BytesWritten = BytesToWrite;

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    UNREFERENCED_PARAMETER(ExitStatus);
    ProcessTerminate(NULL);

    return STATUS_SUCCESS;
}
// syscall thread exit

//ThreadExit(ExitStatus)

// add includ "thread.h"

STATUS
SyscallThreadGetTid(
    IN_OPT  UM_HANDLE               ThreadHandle,
    OUT     TID*                    ThreadId
)
{
    STATUS status = MmuIsBufferValid(
        ThreadId,
        sizeof(ThreadId),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for SyscallThreadGetTid", status);
        return status;
    }

    if(ThreadHandle == UM_INVALID_HANDLE_VALUE)
    {
        *ThreadId = ThreadGetId(NULL);
        return STATUS_SUCCESS;
    }

    // if(&HandleThreadPairsList == NULL)
    //     return STATUS_INTERNAL_ERROR;

    // PLIST_ENTRY pCurrentEntry;

    // pCurrentEntry = HandleThreadPairsList.List.Flink;

    // while(pCurrentEntry != &HandleThreadPairsList.List)
    // {
    //     PHandleThreadPair currentListElement = CONTAINING_RECORD(&pCurrentEntry, HandleThreadPair, List);
        
    //     if(currentListElement->UmHandle == ThreadHandle)
    //     {
    //         *ThreadId = currentListElement->PThread->Id;
    //         return STATUS_SUCCESS;
    //     }

    //     pCurrentEntry = pCurrentEntry->Flink;
    // }

    return STATUS_INTERNAL_ERROR;
}

STATUS
SyscallThreadGetName(
    OUT char* ThreadName,
    IN QWORD ThreadNameMaxLen
    )
{
    STATUS status = MmuIsBufferValid(
        ThreadName,
        sizeof(ThreadName),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for SyscallThreadGetName", status);
        return status;
    }

    cl_strncpy(ThreadName, GetCurrentThread()->Name, (DWORD) ThreadNameMaxLen);

    status = STATUS_SUCCESS;

    if(ThreadNameMaxLen > strlen(ThreadName))
        status = STATUS_TRUNCATED_THREAD_NAME;

    return status;
}

STATUS 
SyscallGetTotalThreadNo(
    OUT QWORD* ThreadNo
    )
{
    STATUS status = MmuIsBufferValid(
        ThreadNo,
        sizeof(ThreadNo),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for SyscallGetTotalThreadNo", status);
        return status;
    }

    *ThreadNo = (QWORD) _GetNumberReadyThreads();

    return STATUS_SUCCESS;
}

STATUS 
SyscallGetThreadUmStackAddress(
    OUT PVOID* StackBaseAddress
    )
{
    STATUS status = MmuIsBufferValid(
        StackBaseAddress,
        sizeof(StackBaseAddress),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for SyscallGetThreadUmStackAddress", status);
        return status;
    }

    *StackBaseAddress = GetCurrentThread()->UserStack;
    return STATUS_SUCCESS;
}

STATUS
SyscallGetThreadUmStackSize(
    OUT QWORD* StackSize
    )
{
    STATUS status = MmuIsBufferValid(
        StackSize,
        sizeof(StackSize),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for SyscallGetThreadUmStackSize", status);
        return status;
    }

    *StackSize = GetCurrentThread()->StackSize;
    return STATUS_SUCCESS;
}

STATUS 
SyscallGetThreadUmEntryPoint(
    OUT PVOID* EntryPoint
    )
{
    STATUS status = MmuIsBufferValid(
        EntryPoint,
        sizeof(EntryPoint),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid for SyscallGetThreadUmEntryPoint", status);
        return status;
    }

    *EntryPoint = GetCurrentThread()->EntryPoint;
    return STATUS_SUCCESS;
}

STATUS
SyscallVirtualAlloc(
    IN_OPT      PVOID                   BaseAddress,
    IN          QWORD                   Size,
    IN          VMM_ALLOC_TYPE          AllocType,
    IN          PAGE_RIGHTS             PageRights,
    IN_OPT      UM_HANDLE               FileHandle,
    IN_OPT      QWORD                   Key,
    OUT         PVOID*                  AllocatedAddress
    )
{
    // UNREFERENCED_PARAMETER(FileHandle)
    // UNREFERENCED_PARAMETER(Key)
    // UNREFERENCED_PARAMETER(AllocatedAddress)

    DWORD nrInvalidParams = 0;

    if(!(BaseAddress == NULL))
        nrInvalidParams++;

    if(!(FileHandle == UM_INVALID_HANDLE_VALUE))
        nrInvalidParams++;
    
    if(!(Key == 0))
        nrInvalidParams++;

    if(nrInvalidParams == 1)
        return STATUS_INVALID_PARAMETER1; 

    if(nrInvalidParams == 2)
        return STATUS_INVALID_PARAMETER2;

    if(nrInvalidParams == 3)
        return STATUS_INVALID_PARAMETER3;

    STATUS status = MmuIsBufferValid(
        AllocatedAddress,
        sizeof(AllocatedAddress),
        PAGE_RIGHTS_ALL,
        GetCurrentProcess()
    );

    if(!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("AllocatedAddress for SyscallVirtualAlloc", status);
        return status;
    }

    AllocatedAddress = VmmAllocRegion(
        BaseAddress,
        Size,
        AllocType,
        PageRights
        );

    return STATUS_SUCCESS;
}

STATUS
SyscallVirtualFree(
    IN          PVOID                   Address,
    _When_(VMM_FREE_TYPE_RELEASE == FreeType, _Reserved_)
    _When_(VMM_FREE_TYPE_RELEASE != FreeType, IN)
                QWORD                   Size,
    IN          VMM_FREE_TYPE           FreeType
    )
{
    VmmFreeRegion(Address, Size, FreeType);
    return STATUS_SUCCESS;
}

STATUS 
SyscallGetPageFaultNo(
    IN PVOID AllocatedVirtAddr,
    OUT QWORD* PageFaultNo
    )
{

}