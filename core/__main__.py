import sys

sys.path.append("../qiling_core/qiling")
from qiling import *
from qiling.os.fncc import *
from qiling.os.windows.utils import *

from capstone import *
from keystone import *

from r2pipe import *

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from pefile import *

def check_format(path):
    meta_data = {}

    with open(path, "rb") as f:
        magic_number = hex(f.read(1))

        if magic_number == 0x7f:
            arch = ELFFile(f).get_machine_arch()
            print(arch)
            return 

        elif magic_number == 0x4d:
            return "windows"
        
        elif magic_number == 0xcf:
            return "macho"

class b0x_MalzBox:
    def __init__(self, path):
        
        pass