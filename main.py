import sys

sys.path.append("api_core/qiling/")

from qiling import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *

from capstone import *
from keystone import *

from r2pipe import *

from angr import *

from core.malz import b0x_MalzBox

from triton import *

m4lz = b0x_MalzBox("/media/sf_MalzBox/api_core/qiling/examples/rootfs/x8664_windows/bin/x8664_hello.exe")

print(m4lz.arch)

m4lz.userland = True
m4lz.tracing()

m4lz.ql.run()

#m4lz.set_triton_trace(m4lz.raw_trace)

#m4lz.static_disass_elf()

m4lz.static_disass_pe(m4lz.file)

for addr in b0x_MalzBox.inst_dic_global:

    inst = b0x_MalzBox.inst_dic_global[addr]

    dic_reg = m4lz.reg_trace[addr]

    preg_dic = m4lz.mdata_regs_trace[addr]

    print("{} : {}".format(addr, inst))
"""
    for reg, value in dic_reg.items():
        print("{} : {}".format(reg, value))

    print(str(m4lz.raw_trace[addr]))
"""
print(hex(m4lz.addr_inst_one))
print(hex(m4lz.static_ep))
range_ep = m4lz.addr_inst_one - m4lz.static_ep # min 0 pas d'ecart

for sec_name, dic_addr_inst in m4lz.op_exec.items():
    print("{} : ".format(sec_name))
    __k_ = 0

    for addr, inst_dic in dic_addr_inst.items():
        for mnem, op in inst_dic.items():
            for __addr_, inst in b0x_MalzBox.inst_dic_global.items():
                if __addr_ == hex(range_ep + addr):
                    __k_ = 1

            if __k_ == 1:
                print("\t{} : {} {} ; #".format(hex(addr), mnem, op))
            else:
                print("\t{} : {} {}".format(hex(addr), mnem, op))
            
            __k_ = 0
