using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace Shared
{
    // ref to https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c
    public unsafe static class MemoryLibrary
    {
        static ushort Endian(ushort num)
        {
            return (ushort)((num << 8) | (num >> 8));
        }
        //static void memcpy(byte* dest, byte* src, uint size)
        //{
        //    for (uint i = 0; i < size; i++)
        //    {
        //        *(dest + i) = *(src + i);
        //    }
        //}
        //static void memset(byte* dest, byte c, uint size)
        //{
        //    for (uint i = 0; i < size; i++)
        //    {
        //        *dest = c;
        //    }
        //}
        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memcpy(byte* dest, byte* src, UIntPtr count);
        [DllImport("msvcrt.dll", EntryPoint = "memset", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memset(IntPtr dest, int c, UIntPtr count);

        #region IMAGE_DOS_HEADER
        const ushort IMAGE_DOS_SIGNATURE = 0x4D5A;	 // MZ
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_DOS_HEADER				 // DOS .EXE header
        {
            public ushort e_magic;					 // Magic number
            public ushort e_cblp;					  // Bytes on last page of file
            public ushort e_cp;						// Pages in file
            public ushort e_crlc;					  // Relocations
            public ushort e_cparhdr;				   // Size of header in paragraphs
            public ushort e_minalloc;				  // Minimum extra paragraphs needed
            public ushort e_maxalloc;				  // Maximum extra paragraphs needed
            public ushort e_ss;						// Initial (relative) SS value
            public ushort e_sp;						// Initial SP value
            public ushort e_csum;					  // Checksum
            public ushort e_ip;						// Initial IP value
            public ushort e_cs;						// Initial (relative) CS value
            public ushort e_lfarlc;					// File address of relocation table
            public ushort e_ovno;					  // Overlay number
            public fixed ushort e_res[4];			  // Reserved ushorts
            public ushort e_oemid;					 // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;				   // OEM information; e_oemid specific
            public fixed ushort e_res2[10];			// Reserved ushorts
            public uint e_lfanew;					  // File address of new exe header
        }
        #endregion
        #region IMAGE_NT_HEADERS
        const byte IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
#if AMD64
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort MachineType;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        public enum File_Characteristics : ushort
        {
            IMAGE_FILE_DLL = 0x2000,
            IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
            IMAGE_FILE_RELOCS_STRIPPED = 0x0001
        }

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }
        #endregion
        #region VirtualAlloc

        [Flags()]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags()]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
           AllocationType flAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize,
           uint dwFreeType);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
           uint flNewProtect, uint* lpflOldProtect);

        //private static extern uint VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        //[DllImport("kernel32.dll")]
        //private static extern int VirtualFree(uint lpAddress, uint dwSize, uint dwFreeType);
        //[DllImport("kernel32.dll")]
        //private static extern int VirtualProtect(uint lpAddress, uint dwSize, uint flNewProtect, uint* lpflOldProtect);
        const uint PAGE_NOACCESS = 0x01;
        const uint PAGE_READONLY = 0x02;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_WRITECOPY = 0x08;
        const uint PAGE_EXECUTE = 0x10;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        const uint PAGE_GUARD = 0x100;
        const uint PAGE_NOCACHE = 0x200;
        const uint PAGE_WRITECOMBINE = 0x400;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_DECOMMIT = 0x4000;
        const uint MEM_RELEASE = 0x8000;
        const uint MEM_FREE = 0x10000;
        const uint MEM_PRIVATE = 0x20000;
        const uint MEM_MAPPED = 0x40000;
        const uint MEM_RESET = 0x80000;
        const uint MEM_TOP_DOWN = 0x100000;
        const uint MEM_WRITE_WATCH = 0x200000;
        const uint MEM_PHYSICAL = 0x400000;
        const uint MEM_LARGE_PAGES = 0x20000000;
        const uint MEM_4MB_PAGES = 0x80000000;
        #endregion

        public struct MEMORYMODULE
        {
            public IMAGE_NT_HEADERS* headers;
            public IntPtr codeBase;

            public IntPtr modules;

            public uint numModules;
            public int initialized;
        }

        delegate bool DllEntryPointFunc(IntPtr hInstDll, UInt32 fdwReason, IntPtr lpvReserved);
        delegate int ExeEntryPointFunc();
        #region IMAGE_SECTION_HEADER
        const int IMAGE_SIZEOF_SHORT_NAME = 8;
        const uint IMAGE_SCN_CNT_CODE = 0x00000020;  // Section contains code.
        const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;  // Section contains initialized data.
        const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080; // Section contains uninitialized data.
        const uint IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;  // Section contains extended relocations.
        const uint IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;  // Section can be discarded.
        const uint IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;   // Section is not cachable.
        const uint IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;	// Section is not pageable.
        const uint IMAGE_SCN_MEM_SHARED = 0x10000000;	   // Section is shareable.
        const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;	  // Section is executable.
        const uint IMAGE_SCN_MEM_READ = 0x40000000;		 // Section is readable.
        const uint IMAGE_SCN_MEM_WRITE = 0x80000000;		// Section is writeable.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_SECTION_HEADER
        {
            public fixed byte Name[IMAGE_SIZEOF_SHORT_NAME];
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }
        static uint[, ,] ProtectionFlags = new uint[2, 2, 2]{
	{
		// not executable
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE},
	}, {
		// executable
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
	},};
        static IMAGE_SECTION_HEADER* IMAGE_FIRST_SECTION(IMAGE_NT_HEADERS* img)
        {
            return (IMAGE_SECTION_HEADER*)((ulong)img + 0x18 + img->FileHeader.SizeOfOptionalHeader);
        }
        static void CopySections(byte* data, IMAGE_NT_HEADERS* old_headers, MEMORYMODULE* module)
        {
            uint i, size;
            IntPtr codeBase1 = module->codeBase;
#if AMD64
            long codeBaseAddr = (long)codeBase1.ToInt64();
#else
            uint codeBaseAddr = (uint)codeBase1.ToInt64();
#endif
            IntPtr dest;
            IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(module->headers);
            for (i = 0; i < module->headers->FileHeader.NumberOfSections; i++, section++)
            {
                if (section->SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define
                    // uninitialized data
                    size = old_headers->OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        dest = VirtualAlloc(new IntPtr(codeBaseAddr + section->VirtualAddress), size, AllocationType.COMMIT, MemoryProtection.READWRITE);// MEM_COMMIT, PAGE_READWRITE);

                        //section->PhysicalAddress = dest;
                        memset(dest, 0, new UIntPtr(size));
                        section->VirtualSize = (uint)(dest.ToInt64() - codeBase1.ToInt64());
                    }

                    // section is empty
                    continue;
                }

                // commit memory block and copy data from dll
                dest = VirtualAlloc(new IntPtr(codeBaseAddr + section->VirtualAddress),
                                    section->SizeOfRawData,
                                    AllocationType.COMMIT, MemoryProtection.READWRITE);

                memcpy((byte*)dest.ToPointer(), 
                        (byte*)(data + section->PointerToRawData), 
                        new UIntPtr(section->SizeOfRawData));
                section->VirtualSize = (uint)(dest.ToInt64() - codeBase1.ToInt64());
            }
        }
        static void FinalizeSections(MEMORYMODULE* module)
        {
            IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(module->headers);

            for (int i = 0; i < module->headers->FileHeader.NumberOfSections; i++, section++)
            {
                uint protect, oldProtect, size;
                uint executable = Convert.ToUInt32((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0);
                uint readable = Convert.ToUInt32((section->Characteristics & IMAGE_SCN_MEM_READ) != 0);
                uint writeable = Convert.ToUInt32((section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0);
                if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
                {
                    // section is not needed any more and can safely be freed

                    // course bug not free it at now.
                    IntPtr sectionPhysicalAddress = new IntPtr(section->Name);
#if AMD64
                    IntPtr pToFree = new IntPtr(section->VirtualSize + module->codeBase.ToInt64());
#else
                    IntPtr pToFree = new IntPtr(section->VirtualSize + module->codeBase.ToInt32());
#endif
                    VirtualFree(pToFree,
                        section->SizeOfRawData, MEM_DECOMMIT);
                    continue;
                }
                protect = ProtectionFlags[executable, readable, writeable];
                if ((section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0)
                    protect |= PAGE_NOCACHE;

                // determine size of region
                size = section->SizeOfRawData;
                if (size == 0)
                {
                    if ((section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
                        size = module->headers->OptionalHeader.SizeOfInitializedData;
                    else if ((section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
                        size = module->headers->OptionalHeader.SizeOfUninitializedData;
                }

                if (size > 0)
                {
                    // change memory access flags
#if AMD64
                    IntPtr pToFree = new IntPtr(section->VirtualSize + module->codeBase.ToInt64());
#else
                    IntPtr pToFree = new IntPtr(section->VirtualSize + module->codeBase.ToInt32());
#endif
                    VirtualProtect(pToFree, 
                        section->SizeOfRawData, protect, &oldProtect);
                }


            }
        }
        #endregion
        #region BaseRelocation
        const uint IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;   // Base Relocation Table

        //static IMAGE_DATA_DIRECTORY* GET_HEADER_DICTIONARY(MEMORYMODULE* module, uint idx)
        //{
        //    return (IMAGE_DATA_DIRECTORY*)(&module->headers->OptionalHeader.DataDirectory[idx]);
        //}
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAddress;
            public uint SizeOfBlock;
        }
        const uint IMAGE_SIZEOF_BASE_RELOCATION = 8;
        const uint IMAGE_REL_BASED_ABSOLUTE = 0;
        const uint IMAGE_REL_BASED_HIGH = 1;
        const uint IMAGE_REL_BASED_LOW = 2;
        const uint IMAGE_REL_BASED_HIGHLOW = 3;
        const uint IMAGE_REL_BASED_HIGHADJ = 4;
        const uint IMAGE_REL_BASED_MIPS_JMPADDR = 5;
        const uint IMAGE_REL_BASED_ARM_MOV32T = 7;
        const uint IMAGE_REL_BASED_DIR64 = 10;

        static void PerformBaseRelocation(MEMORYMODULE* module,
#if AMD64
            Int64 delta
#else
            Int32 delta
#endif
)
        {
            uint i;
            byte* codeBase = (byte*)module->codeBase;

            IMAGE_DATA_DIRECTORY* directory = &module->headers->OptionalHeader.BaseRelocationTable;// GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
            if (directory->Size > 0)
            {
                IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(codeBase + directory->VirtualAddress);
                for (; relocation->VirtualAddress > 0; )
                {
                    byte* dest = (byte*)(codeBase + relocation->VirtualAddress);
                    ushort* relInfo = (ushort*)((byte*)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
                    for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++)
                    {
                        uint* patchAddrHL;
                        ushort* patchAddrHS;
                        uint type, offset;

                        // the upper 4 bits define the type of relocation
                        type = (uint)(*relInfo >> 12);
                        // the lower 12 bits define the offset
                        offset = (uint)(*relInfo & 0xfff);

                        switch (type)
                        {
                            case 6:
                            case IMAGE_REL_BASED_ABSOLUTE:
                                // skip relocation
                                break;

                            case IMAGE_REL_BASED_HIGH:
                                patchAddrHS = (ushort*)((uint)dest + offset);
                                *patchAddrHS += (ushort)((delta & 0xFFFF0000) >> 16);
                                break;

                            case IMAGE_REL_BASED_LOW:
                                patchAddrHS = (ushort*)((uint)dest + offset);
                                *patchAddrHS += (ushort)(delta & 0xFFFF);
                                break;

                            case IMAGE_REL_BASED_HIGHLOW:
                                // change complete 32 bit address
                                patchAddrHL = (uint*)((uint)dest + offset);
                                *patchAddrHL += (uint)delta;
                                break;

                            case IMAGE_REL_BASED_DIR64:
                                IntPtr patchAddr64 = new IntPtr(dest + offset);
                                long oldAddr = Marshal.ReadIntPtr(patchAddr64).ToInt64();
                                long newAddr = oldAddr + delta;
                                Marshal.WriteIntPtr(patchAddr64, new IntPtr(newAddr));
                                break;
                            //case IMAGE_REL_BASED_HIGHADJ:
                            //    patchAddrHS = (ushort*)((uint)dest + offset);

                            //    ushort x = *patchAddrHS;
                            //    uint y = (uint)(x << 16);
                            //    uint z = *(relInfo + 1) + delta + 0x00008000;

                            //    *patchAddrHS = (ushort)((y | z) >> 16);

                            //    relInfo++;
                            //    break;
                            //case IMAGE_REL_BASED_MIPS_JMPADDR:
                            //    patchAddrHL = (uint*)((uint)dest + offset);
                            //    uint Temp = ((*patchAddrHL) & 0x3ffffff) << 2;
                            //    Temp += delta;
                            //    *patchAddrHL = (uint)(((*patchAddrHL) & ~0x3ffffff) | ((Temp >> 2) & 0x3ffffff));
                            //    break;
                            //case IMAGE_REL_BASED_ARM_MOV32T:

                            //    break;

                            //case IMAGE_REL_BASED_ABSOLUTE:
                            //    break;
                            //case IMAGE_REL_BASED_HIGH:
                            //    *((WORD*)fixaddr) += HIWORD(delta);
                            //    break;
                            //case IMAGE_REL_BASED_LOW:
                            //    *((WORD*)fixaddr) += LOWORD(delta);
                            //    break;
                            //case IMAGE_REL_BASED_HIGHLOW:
                            //    *((DWORD*)fixaddr) += delta;
                            //    break;
                            //case IMAGE_REL_BASED_HIGHADJ:
                            //    *((WORD*)fixaddr) = HIWORD(
                            //        ((*((WORD*)fixaddr)) << 16) |
                            //        (*(WORD*)(pfe + 1)) + delta + 0x00008000);
                            //    pfe++;
                            //    break;
                            default:
                                Console.WriteLine("Unknown relocation: {0}\n", type);
                                break;
                        }
                    }

                    // advance to next relocation block
                    relocation = (IMAGE_BASE_RELOCATION*)((uint)relocation + relocation->SizeOfBlock);
                }
            }
        }
        #endregion
        #region BuildImportTable
        const uint DLL_PROCESS_ATTACH = 1;
        const uint DLL_THREAD_ATTACH = 2;
        const uint DLL_THREAD_DETACH = 3;
        const uint DLL_PROCESS_DETACH = 0;
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibrary(string lpFileName);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FreeLibrary(IntPtr hModule);
        //[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        //static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, byte* lpProcName);

        const uint IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint Characteristics;			// 0 for terminating null import descriptor
            public uint TimeDateStamp;				  // 0 if not bound,
            // -1 if bound, and real date\time stamp
            //	 in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
            // O.W. date/time stamp of DLL bound to (Old BIND)

            public uint ForwarderChain;				 // -1 if no forwarders
            public uint Name;
            public uint FirstThunk;					 // RVA to IAT (if bound this IAT has actual addresses)
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_IMPORT_BY_NAME
        {
            public ushort Hint;
            public fixed byte Name[1];
        }
        //[DllImport("kernel32.dll")]
        //static extern IntPtr GlobalReAlloc(IntPtr hMem, IntPtr dwBytes, uint uFlags);

        static IntPtr realloc(IntPtr bytes, IntPtr newsize, uint oldsize)
        {

            IntPtr pNew = Marshal.AllocHGlobal(newsize);
            if (bytes != IntPtr.Zero)
            {
                memcpy((byte*)pNew.ToPointer(), (byte*)bytes.ToPointer(), new UIntPtr(oldsize));
                Marshal.FreeHGlobal(bytes);
            }
            return pNew;
        }

        // ref this nice doc/image: http://www.reverse-engineering.info/SystemInformation/iat.html
        static bool BuildImportTable(MEMORYMODULE* module)
        {
            bool result = true;
            IntPtr codeBase1 = module->codeBase;
#if AMD64
            long codeBaseAddr = (long)codeBase1.ToInt64();
#else
            uint codeBaseAddr = (uint)codeBase1.ToInt64();
#endif

            IMAGE_DATA_DIRECTORY* directory = &module->headers->OptionalHeader.ImportTable; //GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
            if (directory->Size > 0)
            {
                IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(codeBaseAddr + directory->VirtualAddress);
                for (; importDesc->Name != 0; importDesc++)
                {
                    IntPtr pDllName = new IntPtr(codeBaseAddr + importDesc->Name);
                    string dllName = Marshal.PtrToStringAnsi(pDllName);

                    IntPtr thunkRef;
                    IntPtr funcRef;
                    IntPtr handle = LoadLibrary(dllName);

                    if (handle == IntPtr.Zero)
                    {
                        result = false;
                        break;
                    }

                    module->modules = realloc(module->modules, new IntPtr(((uint)(module->numModules + 1)) * IntPtr.Size), (uint)((module->numModules) * IntPtr.Size));

                    if (module->modules == null)
                    {
                        result = false;
                        break;
                    }

                    IntPtr modNext = IntPtrExtensions.ElementAt(module->modules, (int)(module->numModules++));
                    Marshal.WriteIntPtr(modNext, handle);

                    if (importDesc->Characteristics != 0)
                    {
                        thunkRef = new IntPtr(codeBaseAddr + importDesc->Characteristics);
                        funcRef = new IntPtr(codeBaseAddr + importDesc->FirstThunk);
                    }
                    else
                    {
                        // no hint table
                        thunkRef = new IntPtr(codeBaseAddr + importDesc->FirstThunk);
                        funcRef = new IntPtr(codeBaseAddr + importDesc->FirstThunk);
                    }
                    for (; Marshal.ReadIntPtr(thunkRef) != IntPtr.Zero; 
                        thunkRef = IntPtrExtensions.Increment(thunkRef),
                        funcRef = IntPtrExtensions.Increment(funcRef))//*thunkRef != 0; thunkRef++, funcRef++)
                    {
                        IntPtr thunkRefData = Marshal.ReadIntPtr(thunkRef);
                        if ((thunkRefData.ToInt64() & 0x80000000) != 0)
                        {
                            IntPtr pa = GetProcAddress(handle, (byte*)(thunkRefData.ToInt32() & 0xffff));
                            Marshal.WriteIntPtr(funcRef, pa);
                            //*funcRef = GetProcAddress(handle, (byte*)(*thunkRef & 0xffff));
                        }
                        else
                        {
                            IMAGE_IMPORT_BY_NAME* thunkData = (IMAGE_IMPORT_BY_NAME*)(codeBaseAddr + Marshal.ReadIntPtr(thunkRef).ToInt64());//*thunkRef);
                            //string procName = Marshal.PtrToStringAnsi(new IntPtr(thunkData->Name));
                            IntPtr pProc = GetProcAddress(handle, thunkData->Name);
                            Marshal.WriteIntPtr(funcRef, pProc);
                            //*funcRef = GetProcAddress(handle, procName);
                        }
                        if (Marshal.ReadIntPtr(funcRef) == IntPtr.Zero)
                        {
                            result = false;
                            break;
                        }
                    }

                    if (!result)
                        break;
                }
            }

            return result;
        }
        #endregion
        const uint IMAGE_DIRECTORY_ENTRY_EXPORT = 0;   // Export Directory
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;	 // RVA from base of image
            public uint AddressOfNames;		 // RVA from base of image
            public uint AddressOfNameOrdinals;  // RVA from base of image
        }
        static bool stricmp(string str, byte* bytes)
        {
            int idx = 0;
            while (*bytes != 0 && idx < str.Length)
            {
                if (str[idx] != *(bytes + idx))
                {
                    return false;
                }
                idx++;
            }
            return true;
        }

        public static IntPtr MemoryLoadLibrary(byte[] bytes, string[] args)
        {
            fixed (byte* b = bytes)
            {
                IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)b;
                if (Endian(dos_header->e_magic) != IMAGE_DOS_SIGNATURE)
                {
                    return IntPtr.Zero;
                }
                IMAGE_NT_HEADERS* old_header = (IMAGE_NT_HEADERS*)(b + dos_header->e_lfanew);

                IntPtr imgBase = (IntPtr)old_header->OptionalHeader.ImageBase;
                IMAGE_NT_HEADERS * ntHeader = (IMAGE_NT_HEADERS*)&(b[dos_header->e_lfanew]);

                IntPtr code = VirtualAlloc(imgBase, old_header->OptionalHeader.SizeOfImage, AllocationType.RESERVE, MemoryProtection.READWRITE);
                // debug. uncommon bellow line to force relocation.
                //code = VirtualAlloc(imgBase, old_header->OptionalHeader.SizeOfImage, AllocationType.RESERVE, MemoryProtection.READWRITE);
                if (code == IntPtr.Zero)
                {
                    if ((ntHeader->FileHeader.Characteristics & (ushort)File_Characteristics.IMAGE_FILE_RELOCS_STRIPPED) != 0)
                    {
                        Console.WriteLine("not relocable");
                        return IntPtr.Zero;
                    }
                    code = VirtualAlloc(IntPtr.Zero, old_header->OptionalHeader.SizeOfImage, AllocationType.RESERVE, MemoryProtection.READWRITE);
                }
                if (code == IntPtr.Zero)
                    return IntPtr.Zero;
                MEMORYMODULE* result = (MEMORYMODULE*)Marshal.AllocHGlobal(sizeof(MEMORYMODULE));
                result->codeBase = code;
                result->numModules = 0;
                result->modules = IntPtr.Zero;
                result->initialized = 0;
                VirtualAlloc(code, old_header->OptionalHeader.SizeOfImage, AllocationType.COMMIT, MemoryProtection.READWRITE);
                IntPtr headers = VirtualAlloc(code, old_header->OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);

                // copy PE header to code
                memcpy((byte*)headers, (byte*)dos_header, new UIntPtr(dos_header->e_lfanew + old_header->OptionalHeader.SizeOfHeaders));
                result->headers = (IMAGE_NT_HEADERS*)&((byte*)(headers))[dos_header->e_lfanew];

                // update position
#if AMD64
                result->headers->OptionalHeader.ImageBase = (ulong)code;
#else
                result->headers->OptionalHeader.ImageBase = (uint)code;
#endif

                // copy sections from DLL file block to new memory location
                CopySections(b, old_header, result);

                // adjust base address of imported data
#if AMD64
                Int64 locationDelta = code.ToInt64() - imgBase.ToInt64();
#else
                Int32 locationDelta = code.ToInt32() - imgBase.ToInt32();
#endif
                if (locationDelta != 0)
                    PerformBaseRelocation(result, locationDelta);

                // load required dlls and adjust function table of imports
                if (!BuildImportTable(result))
                    goto error;

                // mark memory pages depending on section headers and release
                // sections that are marked as "discardable"
                FinalizeSections(result);

                // get entry point of loaded library
                if (result->headers->OptionalHeader.AddressOfEntryPoint != 0)
                {
#if AMD64
                    IntPtr AddressEntry = new IntPtr(code.ToInt64() + result->headers->OptionalHeader.AddressOfEntryPoint);
#else
                    IntPtr AddressEntry = new IntPtr(code.ToInt32() + result->headers->OptionalHeader.AddressOfEntryPoint);
#endif
                    if (AddressEntry == IntPtr.Zero)
                    {
                        goto error;
                    }

                    if ((result->headers->FileHeader.Characteristics & (ushort)File_Characteristics.IMAGE_FILE_DLL) != 0)
                    {
                        // notify library about attaching to process
                        DllEntryPointFunc func = (DllEntryPointFunc)Marshal.GetDelegateForFunctionPointer(AddressEntry, typeof(DllEntryPointFunc));
                        
                        // forge the arguments
                        // use the preserved LPVOID 3rd argument of dllmain
                        // [dword ptr to argc][char** to argv]
                        IntPtr pXarg = Marshal.AllocHGlobal(IntPtr.Size * (args.Length + 2));
                        // argc
                        Marshal.WriteIntPtr(pXarg, 0, new IntPtr(args.Length + 1));
                        // argv[0]
                        string fileLocation = System.Reflection.Assembly.GetExecutingAssembly().Location;
                        IntPtr argv0 = Marshal.StringToHGlobalAnsi(fileLocation);
                        Marshal.WriteIntPtr(pXarg, IntPtr.Size, argv0);
                        // argv[1..*]
                        for (int a = 0; a < args.Length; a++)
                        {
                            IntPtr argx = Marshal.StringToHGlobalAnsi(args[a]);
                            Marshal.WriteIntPtr(pXarg, (a + 2) * IntPtr.Size, argx);
                        }

                        bool successfull = false;
                        try
                        {
                            Console.WriteLine("entry");
                            successfull = func(code, DLL_PROCESS_ATTACH, pXarg);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("error: {0}", ex.ToString());
                        }

                        // free the args
                        for (int k = 1; k < args.Length + 1; k++)
                        {
                            IntPtr pk = IntPtrExtensions.ElementAt(pXarg, k);
                            IntPtr pkVal = Marshal.ReadIntPtr(pk);
                            Marshal.FreeHGlobal(pkVal);
                        }
                        Marshal.FreeHGlobal(pXarg);

                        if (!successfull)
                        {
                            goto error;
                        }
                    }
                    else
                    {
                        ExeEntryPointFunc func = (ExeEntryPointFunc)Marshal.GetDelegateForFunctionPointer(AddressEntry, typeof(ExeEntryPointFunc));
                        
                        int retCode = func();



                        Console.WriteLine("retcode: {0}", retCode);
                    }
                    result->initialized = 1;
                }

                return new IntPtr(result);

            error:
                // cleanup
                //MemoryFreeLibrary(result);
                return IntPtr.Zero;
            }
        }
        public static IntPtr MemoryGetProcAddress(MEMORYMODULE* module, string name)
        {
            IntPtr codeBase1 = ((MEMORYMODULE*)module)->codeBase;
#if AMD64
            long codeBaseAddr = (long)codeBase1.ToInt64();
#else
            uint codeBaseAddr = (uint)codeBase1.ToInt64();
#endif
            int idx = -1;
            uint i;
            IntPtr nameRef;
            Int16 ordinal;
            IMAGE_EXPORT_DIRECTORY* exports;
            IMAGE_DATA_DIRECTORY* directory = &module->headers->OptionalHeader.ExportTable; //GET_HEADER_DICTIONARY((MEMORYMODULE*)module, IMAGE_DIRECTORY_ENTRY_EXPORT);
            if (directory->Size == 0)
                // no export table found
                return IntPtr.Zero;

            exports = (IMAGE_EXPORT_DIRECTORY*)(codeBaseAddr + directory->VirtualAddress);
            if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
                // DLL doesn't export anything
                return IntPtr.Zero;

            // search function name in list of exported names
            nameRef = new IntPtr(codeBaseAddr + exports->AddressOfNames);
            ordinal = Marshal.ReadInt16(new IntPtr(codeBaseAddr + exports->AddressOfNameOrdinals));
            for (i = 0; i < exports->NumberOfNames; i++, nameRef = IntPtrExtensions.Increment(nameRef), ordinal++)
            {
                if (stricmp(name, (byte*)(codeBaseAddr + Marshal.ReadInt32(nameRef))))  //nameRef.ToInt64())))
                {
                    idx = ordinal;
                    break;
                }
            }

            if (idx == -1)
                // exported symbol not found
                return IntPtr.Zero;

            if ((uint)idx > exports->NumberOfFunctions)
                // name <-> ordinal number don't match
                return IntPtr.Zero;

            // AddressOfFunctions contains the RVAs to the "real" functions
            IntPtr pPos = new IntPtr(codeBaseAddr + exports->AddressOfFunctions + (idx * 4));
            int pPosVal = Marshal.ReadInt32(pPos);
            return new IntPtr(codeBaseAddr + pPosVal);
        }
        public static void MemoryFreeLibrary(IntPtr mod)
        {
            int i;
            MEMORYMODULE* module = (MEMORYMODULE*)mod;

            if (module != null)
            {
                if (module->initialized != 0)
                {
                    // get entry point of loaded library
#if AMD64
                    IntPtr DllEntry = new IntPtr(module->codeBase.ToInt64() + module->headers->OptionalHeader.AddressOfEntryPoint);
#else
                    IntPtr DllEntry = new IntPtr(module->codeBase.ToInt32() + module->headers->OptionalHeader.AddressOfEntryPoint);
#endif

                    // notify library about attaching to process
                    DllEntryPointFunc func = (DllEntryPointFunc)Marshal.GetDelegateForFunctionPointer(DllEntry, typeof(DllEntryPointFunc));
                    bool successfull = func(module->codeBase, DLL_PROCESS_DETACH, IntPtr.Zero);

                    module->initialized = 0;
                }

                if (module->modules != null)
                {
                    // free previously opened libraries
                    for (i = 0; i < module->numModules; i++)
                    {
                        IntPtr modi = IntPtrExtensions.ElementAt(module->modules, i);
                        if (modi != IntPtr.Zero)
                            FreeLibrary(modi);
                    }

                    Marshal.FreeHGlobal(module->modules);
                }

                if (module->codeBase != IntPtr.Zero)
                {
                    // release memory of library
                    VirtualFree(module->codeBase, 0, MEM_RELEASE);
                }

                Marshal.FreeHGlobal(new IntPtr(module));
            }
        }
    }
}
