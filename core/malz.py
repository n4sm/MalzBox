import sys

sys.path.append("../api_core/qiling")

from qiling import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *

from capstone import *
from keystone import *

import r2pipe

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

import pefile

from angr import *

from triton import *

def check_format(path):
    arch_bits_os = []

    with open(path, "rb") as f:
        magic_number = ord(f.read(1))

        if magic_number == 0x7f:
            arch = ELFFile(f).get_machine_arch()
            bits = str(ELFFile(f).elfclass)
            arch_bits_os.append(arch)
            arch_bits_os.append(bits)
            arch_bits_os.append("Linux")
            return arch_bits_os

        elif magic_number == 0x4d:
            bin_pe = pefile.PE(path)
            arch = int(bin_pe.FILE_HEADER.Machine)

            if arch == 0x14c:
                arch = "x86"
                bits = "32"

            else:
                arch = "x86-64"
                bits = 64

            arch_bits_os.append(arch)
            arch_bits_os.append(bits)
            arch_bits_os.append("Windows")
            return arch_bits_os

        elif magic_number == 0xcf:
            arch = "x86-64"
            bits = 64
            arch_bits_os.append(arch)
            arch_bits_os.append(bits)
            arch_bits_os.append("Macos")
            print("Not finished for macho binaries")
            return arch_bits_os

class b0x_MalzBox:
    #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    inst_dic_global = {}
    regs_global = {}

    #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    def __init__(self, path, rootfs_extn=False):
        """
        rootfs_extn for a particular arch
        """
        if rootfs_extn == False:
            list_meta_data = check_format(path)

            arch = list_meta_data[0]
            bits = list_meta_data[1]
            os = list_meta_data[2]

            arch_f = ""
            print(arch)

            if arch == "x64" and os == "Linux":
                arch_f = "x8664_linux"

            elif arch == "AArch64":
                arch_f = "arm64_linux"

            elif arch == "ARM":
                arch_f = "arm_linux"

            elif arch == "MIPS":
                arch_f = "mips32el_linux"

            elif arch == "x86" and os == "Linux":
                arch_f = "x86_linux"

            elif arch == "x86-64" and os == "Windows":
                arch_f = "x8664_windows"

            elif arch == "x86" and os == "Windows":
                arch_f = "x86_windows"

            elif arch == "x86-64" and os == "Macos":
                arch_f = "x8664_macos"

            f_path = "api_core/qiling/examples/rootfs/" + arch_f

            ql = Qiling([path], f_path)

        else:
            ql = Qiling([path], rootfs_extn)

        self.ql = ql
        self.bits = bits
        self.count = 0
        self.userland = False
        self.arch = arch_f
        self.reg = {}
        self.reg_trace = {}
        self.raw_trace = {}
        self.mdata_regs = {}
        self.mdata_regs_trace = {}
        self.inst = Instruction()
        self.file = path
        self.op_exec = {}
        self.md = None
        self.inst_count = 0
        self.addr_inst_one = 0
        self.static_ep = 0

    #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    def x64_setup(self):
        reg_x64 = {
            "rax" : hex(self.ql.uc.reg_read(UC_X86_REG_RAX)),
            "rbx" : hex(self.ql.uc.reg_read(UC_X86_REG_RBX)),
            "rcx" : hex(self.ql.uc.reg_read(UC_X86_REG_RCX)),
            "rdx" : hex(self.ql.uc.reg_read(UC_X86_REG_RDX)),
            "rdi" : hex(self.ql.uc.reg_read(UC_X86_REG_RDI)),
            "rsi" : hex(self.ql.uc.reg_read(UC_X86_REG_RSI)),
            "r8" : hex(self.ql.uc.reg_read(UC_X86_REG_R8)),
            "r9" : hex(self.ql.uc.reg_read(UC_X86_REG_R9)),
            "r10" : hex(self.ql.uc.reg_read(UC_X86_REG_R10)),
            "r11" : hex(self.ql.uc.reg_read(UC_X86_REG_R11)),
            "r12" : hex(self.ql.uc.reg_read(UC_X86_REG_R12)),
            "r13" : hex(self.ql.uc.reg_read(UC_X86_REG_R13)),
            "r14" : hex(self.ql.uc.reg_read(UC_X86_REG_R14)),
            "r15" : hex(self.ql.uc.reg_read(UC_X86_REG_R15)),
            "rip" : hex(self.ql.uc.reg_read(UC_X86_REG_RIP)),
            "rbp" : hex(self.ql.uc.reg_read(UC_X86_REG_RBP)),
            "rsp" : hex(self.ql.uc.reg_read(UC_X86_REG_RSP)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "xmn0" : hex(self.ql.uc.reg_read(UC_X86_REG_MM0)),
            "xmn1" : hex(self.ql.uc.reg_read(UC_X86_REG_MM1)),
            "xmn2" : hex(self.ql.uc.reg_read(UC_X86_REG_MM2)),
            "xmn3" : hex(self.ql.uc.reg_read(UC_X86_REG_MM3)),
            "xmn4" : hex(self.ql.uc.reg_read(UC_X86_REG_MM4)),
            "xmn5" : hex(self.ql.uc.reg_read(UC_X86_REG_MM5)),
            "xmn6" : hex(self.ql.uc.reg_read(UC_X86_REG_MM6)),
            "xmn7" : hex(self.ql.uc.reg_read(UC_X86_REG_MM7)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "mnx0" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM0)),
            "mnx1" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM1)),
            "mnx2" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM2)),
            "mnx3" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM3)),
            "mnx4" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM4)),
            "mnx5" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM5)),
            "mnx6" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM6)),
            "mnx7" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM7)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "k0" : hex(self.ql.uc.reg_read(UC_X86_REG_K0)),
            "k1" : hex(self.ql.uc.reg_read(UC_X86_REG_K1)),
            "k2" : hex(self.ql.uc.reg_read(UC_X86_REG_K2)),
            "k3" : hex(self.ql.uc.reg_read(UC_X86_REG_K3)),
            "k4" : hex(self.ql.uc.reg_read(UC_X86_REG_K4)),
            "k5" : hex(self.ql.uc.reg_read(UC_X86_REG_K5)),
            "k6" : hex(self.ql.uc.reg_read(UC_X86_REG_K6)),
            "k7" : hex(self.ql.uc.reg_read(UC_X86_REG_K7)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "st0" : hex(self.ql.uc.reg_read(UC_X86_REG_ST0)),
            "st1" : hex(self.ql.uc.reg_read(UC_X86_REG_ST1)),
            "st2" : hex(self.ql.uc.reg_read(UC_X86_REG_ST2)),
            "st3" : hex(self.ql.uc.reg_read(UC_X86_REG_ST3)),
            "st4" : hex(self.ql.uc.reg_read(UC_X86_REG_ST4)),
            "st5" : hex(self.ql.uc.reg_read(UC_X86_REG_ST5)),
            "st6" : hex(self.ql.uc.reg_read(UC_X86_REG_ST6)),
            "st7" : hex(self.ql.uc.reg_read(UC_X86_REG_ST7)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "fs" : hex(self.ql.uc.reg_read(UC_X86_REG_FS)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "cr0" : hex(self.ql.uc.reg_read(UC_X86_REG_CR0)),
            "cr1" : hex(self.ql.uc.reg_read(UC_X86_REG_CR1)),
            "cr2" : hex(self.ql.uc.reg_read(UC_X86_REG_CR2)),
            "cr3" : hex(self.ql.uc.reg_read(UC_X86_REG_CR3)),
            "cr4" : hex(self.ql.uc.reg_read(UC_X86_REG_CR4)),
            "cr5" : hex(self.ql.uc.reg_read(UC_X86_REG_CR5)),
            "cr6" : hex(self.ql.uc.reg_read(UC_X86_REG_CR6)),
            "cr7" : hex(self.ql.uc.reg_read(UC_X86_REG_CR7)),
            "cr8" : hex(self.ql.uc.reg_read(UC_X86_REG_CR8)),
            "cr9" : hex(self.ql.uc.reg_read(UC_X86_REG_CR9)),
            "cr10" : hex(self.ql.uc.reg_read(UC_X86_REG_CR10)),
            "cr11" : hex(self.ql.uc.reg_read(UC_X86_REG_CR11)),
            "cr12" : hex(self.ql.uc.reg_read(UC_X86_REG_CR12)),
            "cr13" : hex(self.ql.uc.reg_read(UC_X86_REG_CR13)),
            "cr14" : hex(self.ql.uc.reg_read(UC_X86_REG_CR14)),
            "cr15" : hex(self.ql.uc.reg_read(UC_X86_REG_CR15)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= 

            "xmn0" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM0)),
            "xmn1" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM1)),
            "xmn2" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM2)),
            "xmn3" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM3)),
            "xmn4" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM4)),
            "xmn5" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM5)),
            "xmn6" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM6)),
            "xmn7" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM7)),
            "xmn8" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM8)),
            "xmn9" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM9)),
            "xmn10" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM10)),
            "xmn11" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM11)),
            "xmn12" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM12)),
            "xmn13" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM13)),
            "xmn14" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM14)),
            "xmn15" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM15)),
            "xmn16" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM16)),
            "xmn17" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM17)),
            "xmn18" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM18)),
            "xmn19" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM19)),
            "xmn20" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM20)),
            "xmn21" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM21)),
            "xmn22" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM22)),
            "xmn23" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM23)),
            "xmn24" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM24)),
            "xmn25" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM25)),
            "xmn26" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM26)),
            "xmn27" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM27)),
            "xmn28" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM28)),
            "xmn29" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM29)),
            "xmn30" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM30)),
            "xmn31" : hex(self.ql.uc.reg_read(UC_X86_REG_XMM31))

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= 

        }

        return reg_x64

    def x86_setup(self):
        reg_x32 = {

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "eax" : hex(self.ql.uc.reg_read(UC_X86_REG_EAX)),
            "ebx" : hex(self.ql.uc.reg_read(UC_X86_REG_EBX)),
            "ecx" : hex(self.ql.uc.reg_read(UC_X86_REG_ECX)),
            "edx" : hex(self.ql.uc.reg_read(UC_X86_REG_EDX)),
            "edi" : hex(self.ql.uc.reg_read(UC_X86_REG_EDI)),
            "esi" : hex(self.ql.uc.reg_read(UC_X86_REG_ESI)),
            "r8d" : hex(self.ql.uc.reg_read(UC_X86_REG_R8D)),
            "r9d" : hex(self.ql.uc.reg_read(UC_X86_REG_R9D)),
            "r10d" : hex(self.ql.uc.reg_read(UC_X86_REG_R10D)),
            "r11d" : hex(self.ql.uc.reg_read(UC_X86_REG_R11D)),
            "r12d" : hex(self.ql.uc.reg_read(UC_X86_REG_R12D)),
            "r13d" : hex(self.ql.uc.reg_read(UC_X86_REG_R13D)),
            "r14d" : hex(self.ql.uc.reg_read(UC_X86_REG_R14D)),
            "r15d" : hex(self.ql.uc.reg_read(UC_X86_REG_R15D)),
            "eip" : hex(self.ql.uc.reg_read(UC_X86_REG_EIP)),
            "ebp" : hex(self.ql.uc.reg_read(UC_X86_REG_EBP)),
            "esp" : hex(self.ql.uc.reg_read(UC_X86_REG_ESP))

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

        }

        return reg_x32

    def mips32_setup(self):
        reg_mips32 = {
            "r0" : hex(self.ql.uc.reg_read(UC_MIPS_REG_0)),
            "r1" : hex(self.ql.uc.reg_read(UC_MIPS_REG_1)),
            "r2" : hex(self.ql.uc.reg_read(UC_MIPS_REG_2)),
            "r3" : hex(self.ql.uc.reg_read(UC_MIPS_REG_3)),
            "r4" : hex(self.ql.uc.reg_read(UC_MIPS_REG_4)),
            "r5" : hex(self.ql.uc.reg_read(UC_MIPS_REG_5)),
            "r6" : hex(self.ql.uc.reg_read(UC_MIPS_REG_6)),
            "r7" : hex(self.ql.uc.reg_read(UC_MIPS_REG_7)),
            "r8" : hex(self.ql.uc.reg_read(UC_MIPS_REG_8)),
            "r9" : hex(self.ql.uc.reg_read(UC_MIPS_REG_9)),
            "r10" : hex(self.ql.uc.reg_read(UC_MIPS_REG_10)),
            "r11" : hex(self.ql.uc.reg_read(UC_MIPS_REG_11)),
            "r12" : hex(self.ql.uc.reg_read(UC_MIPS_REG_12)),
            "r13" : hex(self.ql.uc.reg_read(UC_MIPS_REG_13)),
            "r14" : hex(self.ql.uc.reg_read(UC_MIPS_REG_14)),
            "r15" : hex(self.ql.uc.reg_read(UC_MIPS_REG_15)),
            "r16" : hex(self.ql.uc.reg_read(UC_MIPS_REG_16)),
            "r17" : hex(self.ql.uc.reg_read(UC_MIPS_REG_17)),
            "r18" : hex(self.ql.uc.reg_read(UC_MIPS_REG_18)),
            "r19" : hex(self.ql.uc.reg_read(UC_MIPS_REG_19)),
            "r20" : hex(self.ql.uc.reg_read(UC_MIPS_REG_20)),
            "r21" : hex(self.ql.uc.reg_read(UC_MIPS_REG_21)),
            "r22" : hex(self.ql.uc.reg_read(UC_MIPS_REG_22)),
            "r23" : hex(self.ql.uc.reg_read(UC_MIPS_REG_23)),
            "r24" : hex(self.ql.uc.reg_read(UC_MIPS_REG_24)),
            "r25" : hex(self.ql.uc.reg_read(UC_MIPS_REG_25)),
            "r26" : hex(self.ql.uc.reg_read(UC_MIPS_REG_26)),
            "r27" : hex(self.ql.uc.reg_read(UC_MIPS_REG_27)),
            "r28" : hex(self.ql.uc.reg_read(UC_MIPS_REG_28)),
            "r29" : hex(self.ql.uc.reg_read(UC_MIPS_REG_29)),
            "r30" : hex(self.ql.uc.reg_read(UC_MIPS_REG_30)),
            "r31" : hex(self.ql.uc.reg_read(UC_MIPS_REG_31)),

        }

        return reg_mips32

    def arm64_setup(self):
        arm_64_reg = {
            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "x0" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X0)),
            "x2" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X1)),
            "x3" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X2)),
            "x4" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X3)),
            "x5" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X4)),
            "x6" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X5)),
            "x7" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X6)),
            "x8" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X8)),
            "x9" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X9)),
            "x10" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X10)),
            "x11" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X11)),
            "x12" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X12)),
            "x13" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X13)),
            "x14" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X14)),
            "x15" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X15)),
            "x16" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X16)),
            "x17" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X17)),
            "x18" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X18)),
            "x19" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X19)),
            "x20" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X20)),
            "x21" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X21)),
            "x22" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X22)),
            "x23" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X23)),
            "x24" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X24)),
            "x25" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X25)),
            "x26" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X26)),
            "x27" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X27)),
            "x28" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X28)),
            "x29" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X29)),
            "x30" : hex(self.ql.uc.reg_read(UC_ARM64_REG_X30)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "pc" : hex(self.ql.uc.reg_read(UC_ARM64_REG_PC))

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

        }


        return arm_64_reg

    def arm_setup(self):
        reg_arm32 = {
            

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

            "pc" : hex(self.ql.uc.reg_read(UC_ARM_REG_PC)),

            #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=UC_ARM_REG_R0

            "r0" : hex(self.ql.uc.reg_read(UC_ARM_REG_R0)),
            "r1" : hex(self.ql.uc.reg_read(UC_ARM_REG_R1)),
            "r2" : hex(self.ql.uc.reg_read(UC_ARM_REG_R2)),
            "r3" : hex(self.ql.uc.reg_read(UC_ARM_REG_R3)),
            "r4" : hex(self.ql.uc.reg_read(UC_ARM_REG_R4)),
            "r5" : hex(self.ql.uc.reg_read(UC_ARM_REG_R5)),
            "r6" : hex(self.ql.uc.reg_read(UC_ARM_REG_R6)),
            "r7" : hex(self.ql.uc.reg_read(UC_ARM_REG_R7)),
            "r8" : hex(self.ql.uc.reg_read(UC_ARM_REG_R8)),
            "r9" : hex(self.ql.uc.reg_read(UC_ARM_REG_R9)),
            "r10" : hex(self.ql.uc.reg_read(UC_ARM_REG_R10)),
            "r11" : hex(self.ql.uc.reg_read(UC_ARM_REG_R11)),
            "r12" : hex(self.ql.uc.reg_read(UC_ARM_REG_R12)),
            "r13" : hex(self.ql.uc.reg_read(UC_ARM_REG_R13)),
            "r14" : hex(self.ql.uc.reg_read(UC_ARM_REG_R14)),
            "r15" : hex(self.ql.uc.reg_read(UC_ARM_REG_R15))

        }

        return reg_arm32

    def setup_reg(self, arch):
        if arch == "x8664_linux":
            reg = self.x64_setup()

        elif arch == "arm64_linux":
            reg = self.arm64_setup()

        elif arch == "arm_linux":
            reg = self.arm_setup()

        elif arch == "mips32el_linux":
            reg = self.mips32_setup()

        elif arch == "x86_linux":
            reg = self.x86_setup()

        elif arch == "x8664_windows":
            reg = self.x64_setup()

        elif arch == "x86_windows":
            reg = self.x86_setup()

        return reg

    #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    def tracing_inst(self, ql, address, size):
        buf_data = ql.mem_read(address, size)

        if self.inst_count == 0:
            self.addr_inst_one = address

        if self.arch == "x8664_linux":
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)

        elif self.arch == "arm64_linux":
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        elif self.arch == "arm_linux":
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        elif self.arch == "mips32el_linux":
            self.md = Cs(CS_ARCH_MIPS, CS_MODE_32)

        elif self.arch == "x86_linux":
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        
        elif self.arch == "x86_windows":
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)

        elif self.arch == "x8664_windows":
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)

        self.raw_trace[hex(address)] = buf_data

        if self.userland == True:
            if "0x7f" in hex(address):
                return

            else:
                for i in self.md.disasm(buf_data, address):
                    b0x_MalzBox.inst_dic_global[hex(address)] = "{} {}".format(i.mnemonic, i.op_str)

        else:
            for i in self.md.disasm(buf_data, address):
                    b0x_MalzBox.inst_dic_global[hex(address)] = "{} {}".format(i.mnemonic, i.op_str)

        self.inst_count += 1

    def tracing_regs(self, ql, address, size):
        self.reg = self.setup_reg(self.arch) # dico

        self.reg_trace[hex(address)] = self.reg

        for reg, val_regs in self.reg.items():
            try:
                self.mdata_regs[reg] = ql.mem_read(int(val_regs, 16), 4) # On try de voir si la val du reg 
                                                                #c'est une addr et si y'a qqch d'intéressant pointé là bas
            except:
                self.mdata_regs[reg] = None

        self.mdata_regs_trace[hex(address)] = self.mdata_regs # On add ça à la grosse trace

    def tracing(self):
        self.ql.hook_code(self.tracing_inst)
        self.ql.hook_code(self.tracing_regs)
    
    #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    def symbolize_arm64(self, Triton):
        Triton.symbolizeRegister(Triton.registers.x0)
        Triton.symbolizeRegister(Triton.registers.x1)
        Triton.symbolizeRegister(Triton.registers.x2)
        Triton.symbolizeRegister(Triton.registers.x3)
        Triton.symbolizeRegister(Triton.registers.x4)
        Triton.symbolizeRegister(Triton.registers.x5)
        Triton.symbolizeRegister(Triton.registers.x6)
        Triton.symbolizeRegister(Triton.registers.x7)
        Triton.symbolizeRegister(Triton.registers.x8)
        Triton.symbolizeRegister(Triton.registers.x9)
        Triton.symbolizeRegister(Triton.registers.x10)
        Triton.symbolizeRegister(Triton.registers.x11)
        Triton.symbolizeRegister(Triton.registers.x12)
        Triton.symbolizeRegister(Triton.registers.x13)
        Triton.symbolizeRegister(Triton.registers.x14)
        Triton.symbolizeRegister(Triton.registers.x15)
        Triton.symbolizeRegister(Triton.registers.x16)
        Triton.symbolizeRegister(Triton.registers.x17)
        Triton.symbolizeRegister(Triton.registers.x18)
        Triton.symbolizeRegister(Triton.registers.x19)
        Triton.symbolizeRegister(Triton.registers.x20)
        Triton.symbolizeRegister(Triton.registers.x21)
        Triton.symbolizeRegister(Triton.registers.x22)
        Triton.symbolizeRegister(Triton.registers.x23)
        Triton.symbolizeRegister(Triton.registers.x24)
        Triton.symbolizeRegister(Triton.registers.x25)
        Triton.symbolizeRegister(Triton.registers.x26)
        Triton.symbolizeRegister(Triton.registers.x27)
        Triton.symbolizeRegister(Triton.registers.x28)
        Triton.symbolizeRegister(Triton.registers.x29)
        Triton.symbolizeRegister(Triton.registers.x30)

    def symbolize_x86_32(self, Triton):
        Triton.symbolizeRegister(Triton.registers.eax)
        Triton.symbolizeRegister(Triton.registers.ebx)
        Triton.symbolizeRegister(Triton.registers.ecx)
        Triton.symbolizeRegister(Triton.registers.edx)
        Triton.symbolizeRegister(Triton.registers.edi)
        Triton.symbolizeRegister(Triton.registers.esi)
        Triton.symbolizeRegister(Triton.registers.ebp)
        Triton.symbolizeRegister(Triton.registers.esp)

    def symbolize_x64(self, Triton):
        Triton.symbolizeRegister(Triton.registers.rax)
        Triton.symbolizeRegister(Triton.registers.rbx)
        Triton.symbolizeRegister(Triton.registers.rcx)
        Triton.symbolizeRegister(Triton.registers.rdx)
        Triton.symbolizeRegister(Triton.registers.rdi)
        Triton.symbolizeRegister(Triton.registers.rsi)
        Triton.symbolizeRegister(Triton.registers.rbp)
        Triton.symbolizeRegister(Triton.registers.rsp)

    def set_triton_trace(self, trace):
        """
        Trace format dictionnary:
            {addr : "raw_opcodes", addr : "raw_opcodes" ...}
        """

        Triton = TritonContext()

        if self.arch == "x8664_linux":
            Triton.setArchitecture(ARCH.X86_64)
            self.symbolize_x64(Triton)

        elif self.arch == "x86_linux":
            Triton.setArchitecture(ARCH.X86)
            self.symbolize_x86_32(Triton)

        elif self.arch == "x8664_windows":
            Triton.setArchitecture(ARCH.X86_64)
            self.symbolize_x64(Triton)

        elif self.arch == "x86_windows":
            Triton.setArchitecture(ARCH.X86)
            self.symbolize_x86_32(Triton)

        elif self.arch == "arm64_linux":
            Triton.setArchitecture(ARCH.AARCH64)
            self.symbolize_arm64(Triton)

        # https://en.wikipedia.org/wiki/Abstract_syntax_tree

        for addr, opcode in trace.items():
            self.inst.setOpcode(bytes(opcode))

            Triton.processing(self.inst)
            astCtxt = Triton.getAstContext()

            #__inst_ = b0x_MalzBox.inst_dic_global[hex(addr)]

            if self.inst.isBranch():
                if addr in b0x_MalzBox.inst_dic_global.keys():
                    op_ast = Triton.getPathPredicate()
                    model = Triton.getModel(astCtxt.lnot(op_ast))

                    print(model)

                    print("{} {}; Branch instruction".format(addr, b0x_MalzBox.inst_dic_global[addr]))
                else:
                    continue

    #=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    
    def static_disassembly(self) -> None:
        """
        Setup self.exec_op ( {str_name : {hex(addr) : {mnemonic : op_str}} )
        """
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)


    def static_disass_elf(self):
        with open(self.file, "rb") as f:

            e = ELFFile(f)
            self.static_ep = e.header['e_entry']
            op_tmp = {}
            for sec in e.iter_sections():
                if sec["sh_flags"] == 0x6:
                    raw_op = sec.data()
                    for i in self.md.disasm(raw_op, int(sec["sh_addr"])):
                        inst_static_tmp = {i.mnemonic : i.op_str}
                        op_tmp[i.address] = inst_static_tmp

                    self.op_exec[sec.name] = op_tmp
                    op_tmp = {}

    def static_disass_pe(self, filename : str) -> None:
        try:
            pe = pefile.PE(filename)
            epoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.static_ep = epoint

            for section in pe.sections:
                if section.Characteristics & 0x20000000 != 0x20000000:
                    continue

                raw_op = section.get_data()
                op_tmp = {}

                for i in self.md.disasm(raw_op, section.VirtualAddress):
                       inst_static_tmp = {i.mnemonic : i.op_str}
                       op_tmp[i.address] = inst_static_tmp

                self.op_exec[str(section.Name.decode('utf-8').replace("\0", ""))] = op_tmp


        except Exception as exc:
            print(exc)
        return None

    def _get_section_from_rva(self, pe : pefile.PE, rva_pointer : int):
        for section in pe.sections:
            if section.contains_rva(rva_pointer):
                return section
        return None

    def extract_opcodes(self, filename : str) -> bytearray:
        try:
            pe = pefile.PE(filename)
            epoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.static_ep = epoint
            esection = _get_section_from_rva(pe, epoint)
            if not esection:
                print("[-] Failed getting opcodes")
                return None
            return bytearray(esection.get_data())
        except Exception as exc:
            print(exc)
        return None

# Today, the role of the traditional social media has changed with the increase of 
# the information on the web. For all of us, it is essential to stay abreast of the 
# latest news. But with the advent of mass information, this role is no longer reserved 
# or the mainstream media. Anyone can have visibility and spread some information, and this can
# impact as much as a traditional media. These changes have therefore led to a drop in audiences and in the attention paid to them.
# This multiplication of information has two main impacts: the disappearance 
# of censorship and a more raw access to information and the birth of fake news.
# This democratization of knowledge and information is one of the great characteristics of the Internet. 
# Everyone can have access to news in real time, directly on social networks through a video.or on 
# any websites.
# This notion of instantaneity characterizes today our relationship with the media.
# As this information does not pass through traditional media, the information arrives to us raw uncensored but also unprocessed 
# and it is up to us to succeed in finding reliable information among many others.
# For example, we can quote wikileaks, a group of activists who distribute documents classified as secret
# or censored in order to offer raw information to everyone. However, these practices 
# can be dangerous because they can compromise the lives of people still involved.
# But as we saw earlier, it is not easy to sort out reliable information among all that offered. 
# Thus proliferate fake news and other rumors. With the advent of the internet, they are 
# everywhere and seem as the price to pay for accessing this bud of information.