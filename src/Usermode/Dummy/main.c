#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

STATUS
__main(
    DWORD       argc,
    char**      argv
)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    STATUS status;

    for ( QWORD ThreadNameMaxLen = 1 ; ThreadNameMaxLen < 5; ThreadNameMaxLen ++)
    {
        char ThreadName[255];

        status = SyscallThreadGetName ( ThreadName , ThreadNameMaxLen );

        if (! SUCCEEDED ( status ))
        {
            LOG_FUNC_ERROR (" SyscallThreadGetName ", status );
            continue;
        }

        LOG (" ThreadName -> %s", ThreadName );
    }

    QWORD ThreadNo;
    status = SyscallGetTotalThreadNo ( &ThreadNo );

    if (! SUCCEEDED ( status ))
    {
        LOG_FUNC_ERROR ("SyscallGetTotalThreadNo", status );
    }

    LOG (" Ready threads nr -> %llu", ( QWORD ) ThreadNo );


    PVOID StackBaseAddress;
    status = SyscallGetThreadUmStackAddress ( &StackBaseAddress );

    if (! SUCCEEDED ( status ))
    {
        LOG_FUNC_ERROR (" SyscallGetThreadUmStackAddress ", status );
    }

    LOG (" Stack Base Address -> %d", ( QWORD ) StackBaseAddress );


    PVOID EntryPoint;
    status = SyscallGetThreadUmEntryPoint ( &EntryPoint );

    if (! SUCCEEDED ( status ))
    {
        LOG_FUNC_ERROR (" SyscallGetThreadUmEntryPoint ", status );
    }

    LOG (" Process Entry Point -> %d", ( QWORD ) EntryPoint );


    TID ThreadId;
    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &ThreadId);

    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR(" SyscallThreadGetTid ", status);
    }

    LOG(" SyscallThreadGetTid -> %d", ThreadId);

    return STATUS_SUCCESS;
}