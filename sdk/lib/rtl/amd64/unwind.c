/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * PURPOSE:         Unwinding related functions
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <rtl.h>

#define NDEBUG
#include <debug.h>

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

#define UWOP_PUSH_NONVOL 0
#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2
#define UWOP_SET_FPREG 3
#define UWOP_SAVE_NONVOL 4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM 6
#define UWOP_SAVE_XMM_FAR 7
#define UWOP_SAVE_XMM128 8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10


typedef unsigned char UBYTE;

typedef union _UNWIND_CODE
{
    struct
    {
        UBYTE CodeOffset;
        UBYTE UnwindOp:4;
        UBYTE OpInfo:4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO
{
    UBYTE Version:3;
    UBYTE Flags:5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister:4;
    UBYTE FrameOffset:4;
    UNWIND_CODE UnwindCode[1];
/*    union {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };
    OPTIONAL ULONG ExceptionData[];
*/
} UNWIND_INFO, *PUNWIND_INFO;

/* FUNCTIONS *****************************************************************/

/*! RtlLookupFunctionTable
 * \brief Locates the table of RUNTIME_FUNCTION entries for a code address.
 * \param ControlPc
 *            Address of the code, for which the table should be searched.
 * \param ImageBase
 *            Pointer to a DWORD64 that receives the base address of the
 *            corresponding executable image.
 * \param Length
 *            Pointer to an ULONG that receives the number of table entries
 *            present in the table.
 */
PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionTable(
    IN DWORD64 ControlPc,
    OUT PDWORD64 ImageBase,
    OUT PULONG Length)
{
    PVOID Table;
    ULONG Size;

    /* Find corresponding file header from code address */
    if (!RtlPcToFileHeader((PVOID)ControlPc, (PVOID*)ImageBase))
    {
        /* Nothing found */
        return NULL;
    }

    /* Locate the exception directory */
    Table = RtlImageDirectoryEntryToData((PVOID)*ImageBase,
                                         TRUE,
                                         IMAGE_DIRECTORY_ENTRY_EXCEPTION,
                                         &Size);

    /* Return the number of entries */
    *Length = Size / sizeof(RUNTIME_FUNCTION);

    /* Return the address of the table */
    return Table;
}

/*! RtlLookupFunctionEntry
 * \brief Locates the RUNTIME_FUNCTION entry corresponding to a code address.
 * \ref http://msdn.microsoft.com/en-us/library/ms680597(VS.85).aspx
 * \todo Implement HistoryTable
 */
PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionEntry(
    IN DWORD64 ControlPc,
    OUT PDWORD64 ImageBase,
    OUT PUNWIND_HISTORY_TABLE HistoryTable)
{
    PRUNTIME_FUNCTION FunctionTable, FunctionEntry;
    ULONG TableLength;
    ULONG IndexLo, IndexHi, IndexMid;

    /* Find the corresponding table */
    FunctionTable = RtlLookupFunctionTable(ControlPc, ImageBase, &TableLength);

    /* Fail, if no table is found */
    if (!FunctionTable)
    {
        return NULL;
    }

    /* Use relative virtual address */
    ControlPc -= *ImageBase;

    /* Do a binary search */
    IndexLo = 0;
    IndexHi = TableLength;
    while (IndexHi > IndexLo)
    {
        IndexMid = (IndexLo + IndexHi) / 2;
        FunctionEntry = &FunctionTable[IndexMid];

        if (ControlPc < FunctionEntry->BeginAddress)
        {
            /* Continue search in lower half */
            IndexHi = IndexMid;
        }
        else if (ControlPc >= FunctionEntry->EndAddress)
        {
            /* Continue search in upper half */
            IndexLo = IndexMid + 1;
        }
        else
        {
            /* ControlPc is within limits, return entry */
            return FunctionEntry;
        }
    }

    /* Nothing found, return NULL */
    return NULL;
}

BOOLEAN
NTAPI
RtlAddFunctionTable(
    IN PRUNTIME_FUNCTION FunctionTable,
    IN DWORD EntryCount,
    IN DWORD64 BaseAddress)
{
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
NTAPI
RtlDeleteFunctionTable(
    IN PRUNTIME_FUNCTION FunctionTable)
{
    UNIMPLEMENTED;
    return FALSE;
}

BOOLEAN
NTAPI
RtlInstallFunctionTableCallback(
    IN DWORD64 TableIdentifier,
    IN DWORD64 BaseAddress,
    IN DWORD Length,
    IN PGET_RUNTIME_FUNCTION_CALLBACK Callback,
    IN PVOID Context,
    IN PCWSTR OutOfProcessCallbackDll)
{
    UNIMPLEMENTED;
    return FALSE;
}

void
FORCEINLINE
SetReg(PCONTEXT Context, BYTE Reg, DWORD64 Value)
{
    ((DWORD64*)(&Context->Rax))[Reg] = Value;
}

DWORD64
FORCEINLINE
GetReg(PCONTEXT Context, BYTE Reg)
{
    return ((DWORD64*)(&Context->Rax))[Reg];
}

void
FORCEINLINE
PopReg(PCONTEXT Context, BYTE Reg)
{
    DWORD64 Value = *(DWORD64*)Context->Rsp;
    Context->Rsp += 8;
    SetReg(Context, Reg, Value);
}

/*! RtlpTryToUnwindEpilog
 * \brief Helper function that tries to unwind epilog instructions.
 * \return TRUE if we have been in an epilog and it could be unwound.
 *         FALSE if the instructions were not allowed for an epilog.
 * \ref
 *  http://msdn.microsoft.com/en-us/library/8ydc79k6(VS.80).aspx
 *  http://msdn.microsoft.com/en-us/library/tawsa7cb.aspx
 * \todo
 *  - Test and compare with Windows behaviour
 */
BOOLEAN
static
__inline
RtlpTryToUnwindEpilog(
    PCONTEXT Context,
    ULONG64 ImageBase,
    PRUNTIME_FUNCTION FunctionEntry)
{
    CONTEXT LocalContext;
    BYTE *InstrPtr;
    DWORD Instr;
    BYTE Reg, Mod;
    ULONG64 EndAddress;

    /* Make a local copy of the context */
    LocalContext = *Context;

    InstrPtr = (BYTE*)LocalContext.Rip;

    /* Check if first instruction of epilog is "add rsp, x" */
    Instr = *(DWORD*)InstrPtr;
    if ( (Instr & 0x00fffdff) == 0x00c48148 )
    {
        if ( (Instr & 0x0000ff00) == 0x8300 )
        {
            /* This is "add rsp, 0x??" */
            LocalContext.Rsp += Instr >> 24;
            InstrPtr += 4;
        }
        else
        {
            /* This is "add rsp, 0x???????? */
            LocalContext.Rsp += *(DWORD*)(InstrPtr + 3);
            InstrPtr += 7;
        }
    }
    /* Check if first instruction of epilog is "lea rsp, ..." */
    else if ( (Instr & 0x38fffe) == 0x208d48 )
    {
        /* Get the register */
        Reg = ((Instr << 8) | (Instr >> 16)) & 0x7;

        LocalContext.Rsp = GetReg(&LocalContext, Reg);

        /* Get adressing mode */
        Mod = (Instr >> 22) & 0x3;
        if (Mod == 0)
        {
            /* No displacement */
            InstrPtr += 3;
        }
        else if (Mod == 1)
        {
            /* 1 byte displacement */
            LocalContext.Rsp += Instr >> 24;
            InstrPtr += 4;
        }
        else if (Mod == 2)
        {
            /* 4 bytes displacement */
            LocalContext.Rsp += *(DWORD*)(InstrPtr + 3);
            InstrPtr += 7;
        }
    }

    /* Loop the following instructions before the ret */
    EndAddress = FunctionEntry->EndAddress + ImageBase - 1;
    while ((DWORD64)InstrPtr < EndAddress)
    {
        Instr = *(DWORD*)InstrPtr;

        /* Check for a simple pop */
        if ( (Instr & 0xf8) == 0x58 )
        {
            /* Opcode pops a basic register from stack */
            Reg = Instr & 0x7;
            PopReg(&LocalContext, Reg);
            InstrPtr++;
            continue;
        }

        /* Check for REX + pop */
        if ( (Instr & 0xf8fb) == 0x5841 )
        {
            /* Opcode is pop r8 .. r15 */
            Reg = ((Instr >> 8) & 0x7) + 8;
            PopReg(&LocalContext, Reg);
            InstrPtr += 2;
            continue;
        }

        /* Opcode not allowed for Epilog */
        return FALSE;
    }

    /* Check if we are at the ret instruction */
    if ((DWORD64)InstrPtr != EndAddress)
    {
        /* If we went past the end of the function, something is broken! */
        ASSERT((DWORD64)InstrPtr <= EndAddress);
        return FALSE;
    }

    /* Make sure this is really a ret instruction */
    if (*InstrPtr != 0xc3)
    {
        ASSERT(FALSE);
        return FALSE;
    }

    /* Unwind is finished, pop new Rip from Stack */
    LocalContext.Rip = *(DWORD64*)LocalContext.Rsp;
    LocalContext.Rsp += sizeof(DWORD64);

    *Context = LocalContext;
    return TRUE;
}

PEXCEPTION_ROUTINE
NTAPI
RtlVirtualUnwind(
    _In_ ULONG HandlerType,
    _In_ ULONG64 ImageBase,
    _In_ ULONG64 ControlPc,
    _In_ PRUNTIME_FUNCTION FunctionEntry,
    _Inout_ PCONTEXT Context,
    _Outptr_ PVOID *HandlerData,
    _Out_ PULONG64 EstablisherFrame,
    _Inout_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
{
    PUNWIND_INFO UnwindInfo;
    ULONG_PTR CodeOffset;
    ULONG i;
    UNWIND_CODE UnwindCode;
    BYTE Reg;
    PULONG LanguageHandler;

    /* Use relative virtual address */
    ControlPc -= ImageBase;

    /* Sanity checks */
    if ( (ControlPc < FunctionEntry->BeginAddress) ||
         (ControlPc >= FunctionEntry->EndAddress) )
    {
        return NULL;
    }

    /* Get a pointer to the unwind info */
    UnwindInfo = RVA(ImageBase, FunctionEntry->UnwindData);

    /* The language specific handler data follows the unwind info */
    LanguageHandler = ALIGN_UP_POINTER_BY(&UnwindInfo->UnwindCode[UnwindInfo->CountOfCodes], sizeof(ULONG));
    *HandlerData = (LanguageHandler + 1);

    /* Calculate relative offset to function start */
    CodeOffset = ControlPc - FunctionEntry->BeginAddress;

    /* Check if we are in the function epilog and try to finish it */
    if (CodeOffset > UnwindInfo->SizeOfProlog)
    {
        if (RtlpTryToUnwindEpilog(Context, ImageBase, FunctionEntry))
        {
            /* There's no exception routine */
            return NULL;
        }
    }

    /* Skip all Ops with an offset greater than the current Offset */
    i = 0;
    while (i < UnwindInfo->CountOfCodes &&
           CodeOffset < UnwindInfo->UnwindCode[i].CodeOffset)
    {
        UnwindCode = UnwindInfo->UnwindCode[i];
        switch (UnwindCode.UnwindOp)
        {
            case UWOP_SAVE_NONVOL:
            case UWOP_SAVE_XMM:
            case UWOP_SAVE_XMM128:
                i += 2;
                break;

            case UWOP_SAVE_NONVOL_FAR:
            case UWOP_SAVE_XMM_FAR:
            case UWOP_SAVE_XMM128_FAR:
                i += 3;
                break;

            case UWOP_ALLOC_LARGE:
                i += UnwindCode.OpInfo ? 3 : 2;
                break;

            default:
                i++;
        }
    }

    /* Process the remaining unwind ops */
    while (i < UnwindInfo->CountOfCodes)
    {
        UnwindCode = UnwindInfo->UnwindCode[i];
        switch (UnwindCode.UnwindOp)
        {
            case UWOP_PUSH_NONVOL:
                Reg = UnwindCode.OpInfo;
                SetReg(Context, Reg, *(DWORD64*)Context->Rsp);
                Context->Rsp += sizeof(DWORD64);
                i++;
                break;

            case UWOP_ALLOC_LARGE:
                if (UnwindCode.OpInfo)
                {
                    ULONG Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i+1]);
                    Context->Rsp += Offset;
                    i += 3;
                }
                else
                {
                    USHORT Offset = UnwindInfo->UnwindCode[i+1].FrameOffset;
                    Context->Rsp += Offset * 8;
                    i += 2;
                }
                break;

            case UWOP_ALLOC_SMALL:
                Context->Rsp += (UnwindCode.OpInfo + 1) * 8;
                i++;
                break;

            case UWOP_SET_FPREG:
                i++;
                break;

            case UWOP_SAVE_NONVOL:
                i += 2;
                break;

            case UWOP_SAVE_NONVOL_FAR:
                i += 3;
                break;

            case UWOP_SAVE_XMM:
                i += 2;
                break;

            case UWOP_SAVE_XMM_FAR:
                i += 3;
                break;

            case UWOP_SAVE_XMM128:
                i += 2;
                break;

            case UWOP_SAVE_XMM128_FAR:
                i += 3;
                break;

            case UWOP_PUSH_MACHFRAME:
                i += 1;
                break;
        }
    }

    /* Unwind is finished, pop new Rip from Stack */
    Context->Rip = *(DWORD64*)Context->Rsp;
    Context->Rsp += sizeof(DWORD64);

    *EstablisherFrame = Context->Rsp;

    if (UnwindInfo->Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
    {
        return RVA(ImageBase, *LanguageHandler);
    }

    return NULL;
}

/*!
    \remark The implementation is based on the description in this blog: http://www.nynaeve.net/?p=106
        The numbers in the comments correspond to the section in the article.

        Differences to the desciption:
        - Instead of using 2 pointers to the unwind context and previous context,
          that are being swapped and the context copied, the unwind context is
          kept in the local context and copied back into the context passed in
          by the caller.
          

    \see http://www.nynaeve.net/?p=106
*/
VOID
NTAPI
RtlUnwindEx(
    _In_opt_ PVOID TargetFrame,
    _In_opt_ PVOID TargetIp,
    _In_opt_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PVOID ReturnValue,
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _UNWIND_HISTORY_TABLE *HistoryTable)
{
    EXCEPTION_RECORD LocalExceptionRecord;
    DISPATCHER_CONTEXT DispatcherContext;
    PEXCEPTION_ROUTINE ExceptionRoutine;
    EXCEPTION_DISPOSITION Disposition;
    ULONG_PTR StackLow, StackHigh;
    ULONG64 ImageBase, EstablisherFrame;
    PRUNTIME_FUNCTION FunctionEntry;
    CONTEXT UnwindContext;
    __debugbreak();

    /* Get the current stack limits and registration frame */
    RtlpGetStackLimits(&StackLow, &StackHigh);

    /* If we have a target frame, then this is our high limit */
    if (TargetFrame != NULL)
    {
        StackHigh = (ULONG64)TargetFrame + 1;
    }

    /* Capture the current context */
    RtlCaptureContext(ContextRecord);

    /* Copy the context */
    UnwindContext = *ContextRecord;

    /* Check if we have an exception record */
    if (ExceptionRecord == NULL)
    {
        /* No exception record was passed, so set up a local one */
        LocalExceptionRecord.ExceptionCode = STATUS_UNWIND;
        LocalExceptionRecord.ExceptionAddress = (PVOID)ContextRecord->Rip;
        LocalExceptionRecord.ExceptionRecord = NULL;
        LocalExceptionRecord.NumberParameters = 0;
        ExceptionRecord = &LocalExceptionRecord;
    }

    /* Set up the constant fields of the dispatcher context */
    DispatcherContext.ContextRecord = &UnwindContext;
    DispatcherContext.ScopeIndex = 0;
    DispatcherContext.HistoryTable = HistoryTable;
    DispatcherContext.TargetIp = (ULONG64)TargetIp;

    /* Loop the frames */
    do
    {
        /* Save the current RIP before unwinding */
        DispatcherContext.ControlPc = UnwindContext.Rip;

        /* Lookup the FunctionEntry for the current RIP (1.) */
        FunctionEntry = RtlLookupFunctionEntry(UnwindContext.Rip, &ImageBase, NULL);

        /* Check if we found a function entry */
        if (FunctionEntry != NULL)
        {
            /* We have a function entry. Use it to do a virtual unwind (2.) */
            ExceptionRoutine = RtlVirtualUnwind(0,
                                                ImageBase,
                                                UnwindContext.Rip,
                                                FunctionEntry,
                                                &UnwindContext,
                                                &DispatcherContext.HandlerData,
                                                &EstablisherFrame,
                                                NULL);
            DPRINT("Nested funtion, new Rip = %p, new Rsp = %p\n", (PVOID)UnwindContext.Rip, (PVOID)UnwindContext.Rsp);

            /* Check, if we have left our stack (3.) */
            if ((EstablisherFrame < StackLow) ||
                (EstablisherFrame > StackHigh) ||
                (EstablisherFrame & 7))
            {
                /// TODO: Handle DPC stack
                __debugbreak();
                RtlRaiseStatus(STATUS_BAD_STACK);
            }

            /* Check if we got an exception routine (4.) */
            if (ExceptionRoutine != NULL)
            {
                /* Check if this is the target frame (5.) */
                if (EstablisherFrame == (ULONG64)TargetFrame)
                {
                    /* Set flag to inform the language handler */
                    ExceptionRecord->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
                }

                /* Set up the remaining fields of the dispatcher context */
                DispatcherContext.ImageBase = (PVOID)ImageBase;
                DispatcherContext.FunctionEntry = FunctionEntry;
                DispatcherContext.LanguageHandler = ExceptionRoutine;
                DispatcherContext.EstablisherFrame = (PVOID)EstablisherFrame;

                /* Check if logging is enabled */
                RtlpCheckLogException(ExceptionRecord,
                                      ContextRecord,
                                      &DispatcherContext,
                                      sizeof(DispatcherContext));

                /* Store the return value in the unwind context */
                UnwindContext.Rax = (ULONG64)ReturnValue;

                /// TODO: call RtlpExecuteHandlerForUnwind instead

                /* Call the language specific handler */
                Disposition = ExceptionRoutine(ExceptionRecord,
                    (PVOID)EstablisherFrame,
                                               &UnwindContext,
                                               &DispatcherContext);

                /* Clear exception flags for the next iteration flags */
                ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND |
                                                     EXCEPTION_COLLIDED_UNWIND);

                /* Handle the dispositions (7.) */
                switch (Disposition)
                {
                    case ExceptionContinueSearch:

                        break;

                    case ExceptionCollidedUnwind:

                        /// TODO
                        __debugbreak();
                        break;

                        /* Anything else */
                    default:

                        __debugbreak();
                        RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
                        break;
                }
            }
        }
        else
        {
            /* No function entry, so this must be a leaf function. Pop the return address from the stack */
            UnwindContext.Rip = *(DWORD64*)UnwindContext.Rsp;
            UnwindContext.Rsp += sizeof(DWORD64);
            DPRINT("Leaf funtion, new Rip = %p, new Rsp = %p\n", (PVOID)UnwindContext.Rip, (PVOID)UnwindContext.Rsp);
        }

        /*
        8. If control reaches this point, then a frame has been
        successfully unwound, and any applicable unwind handler has
        been notified of the unwind operation. The next step is a
        re-validation of the EstablisherFrame value (as it may have
        changed in the collided unwind case). Assuming that
        EstablisherFrame is valid, if its value does not match the
        TargetFrame argument, then control is transferred to step 1.
        Otherwise, if there is a match, then the loop terminates.
        (If the EstablisherFrame is not valid, and is not the expected
        TargetFrame value, then either the unwind exception record is
        raised as an exception, or a STATUS_BAD_FUNCTION_TABLE
        exception is raised.)
        */

        /* Check, if we have left our stack (8.) */
        if ((EstablisherFrame < StackLow) ||
            (EstablisherFrame > StackHigh) ||
            (EstablisherFrame & 7))
        {
            // Check for DPC stack

            __debugbreak();

            if (UnwindContext.Rip == ContextRecord->Rip)
            {
                RtlRaiseStatus(STATUS_BAD_FUNCTION_TABLE);
            }
            else
            {
                ZwRaiseException(ExceptionRecord, ContextRecord, FALSE);
            }
        }

        /* We have successfully unwound a frame. Copy the unwind context back. */
        *ContextRecord = UnwindContext;

    } while ((PVOID)EstablisherFrame != TargetFrame);


    UnwindContext.Rax = (ULONG64)ReturnValue;
    if (ExceptionRecord->ExceptionCode != STATUS_UNWIND_CONSOLIDATE)
    {
        UnwindContext.Rip = (ULONG64)TargetIp;
    }

    RtlRestoreContext(&UnwindContext, ExceptionRecord);
}


VOID
NTAPI
RtlUnwind(
  IN PVOID TargetFrame,
  IN PVOID TargetIp,
  IN PEXCEPTION_RECORD ExceptionRecord,
  IN PVOID ReturnValue)
{
    UNIMPLEMENTED;
    return;
}

ULONG
NTAPI
RtlWalkFrameChain(OUT PVOID *Callers,
                  IN ULONG Count,
                  IN ULONG Flags)
{
    CONTEXT Context;
    ULONG64 ControlPc, ImageBase, EstablisherFrame;
    ULONG64 StackLow, StackHigh;
    PVOID HandlerData;
    ULONG i, FramesToSkip;
    PRUNTIME_FUNCTION FunctionEntry;

    DPRINT("Enter RtlWalkFrameChain\n");

    /* The upper bits in Flags define how many frames to skip */
    FramesToSkip = Flags >> 8;

    /* Capture the current Context */
    RtlCaptureContext(&Context);
    ControlPc = Context.Rip;

    /* Get the stack limits */
    RtlpGetStackLimits(&StackLow, &StackHigh);

    /* Check if we want the user-mode stack frame */
    if (Flags & 1)
    {
    }

    /* Loop the frames */
    for (i = 0; i < FramesToSkip + Count; i++)
    {
        /* Lookup the FunctionEntry for the current ControlPc */
        FunctionEntry = RtlLookupFunctionEntry(ControlPc, &ImageBase, NULL);

        /* Is this a leaf function? */
        if (!FunctionEntry)
        {
            Context.Rip = *(DWORD64*)Context.Rsp;
            Context.Rsp += sizeof(DWORD64);
            DPRINT("leaf funtion, new Rip = %p, new Rsp = %p\n", (PVOID)Context.Rip, (PVOID)Context.Rsp);
        }
        else
        {
            RtlVirtualUnwind(0,
                             ImageBase,
                             ControlPc,
                             FunctionEntry,
                             &Context,
                             &HandlerData,
                             &EstablisherFrame,
                             NULL);
            DPRINT("normal funtion, new Rip = %p, new Rsp = %p\n", (PVOID)Context.Rip, (PVOID)Context.Rsp);
        }

        /* Check if new Rip is valid */
        if (!Context.Rip)
        {
            break;
        }

        /* Check, if we have left our stack */
        if ((Context.Rsp < StackLow) || (Context.Rsp > StackHigh))
        {
            break;
        }

        /* Continue with new Rip */
        ControlPc = Context.Rip;

        /* Save value, if we are past the frames to skip */
        if (i >= FramesToSkip)
        {
            Callers[i - FramesToSkip] = (PVOID)ControlPc;
        }
    }

    DPRINT("RtlWalkFrameChain returns %ld\n", i);
    return i;
}

/*! RtlGetCallersAddress
 * \ref http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/RtlGetCallersAddress.html
 */
#undef RtlGetCallersAddress
VOID
NTAPI
RtlGetCallersAddress(
    OUT PVOID *CallersAddress,
    OUT PVOID *CallersCaller )
{
    PVOID Callers[4];
    ULONG Number;

    /* Get callers:
     * RtlWalkFrameChain -> RtlGetCallersAddress -> x -> y */
    Number = RtlWalkFrameChain(Callers, 4, 0);

    *CallersAddress = (Number >= 3) ? Callers[2] : NULL;
    *CallersCaller = (Number == 4) ? Callers[3] : NULL;

    return;
}

