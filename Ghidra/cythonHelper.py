from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.address import Address
from ghidra.program.model.data import ArrayDataType, IntegerDataType, LongDataType, PointerDataType, StringDataType, StructureDataType
from ghidra.program.model.pcode import *
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
from os import path

CONST = "const"
STACK = "stack"
RAM = "ram"
REG = "register"
UNQ = "unique"

TYPE_MDEF = 0x1
TYPE_STR = 0x2
TYPE_INT = 0x3

FLAG_DST = "(DST)"

NUM_fmt = "__pyx_int_{}"
STR_fmt = "__pyx_n_s_{}"
MOD_fmt = "__pyx_{}"
TUPLE_fmt = "__pyx_tuple_{}_items"
BYTE_fmt = "__pyx__bytes_{}"
CODE_fmt = "__pyx_codeobj_{}"

# file_pointer = None

# def LOG(s):
#     if file_pointer:
#         return file_pointer.write(s + "\n")
#     else:
#         return None

def INFO(s):
    print(f"[+] {s}")
    return

def WARNING(s):
    print(f"> {s}")
    return

def ERROR(s):
    raise RuntimeError(f"[-] {s}")

def printDef(defs, indent=0):
    print("    "*indent + "{")
    for i in range(len(defs)):
        if isinstance(defs[i], type([])):
            printDef(defs[i], indent + 1)
        elif i == 1:
            print("    "*(indent+1) + PcodeOp.getMnemonic(defs[i]))
        elif i == 2 and defs[1] == PcodeOp.CALL:
            print("    "*(indent+1) + getFunctionAt(defs[i]).getName())
        else:
            print("    "*(indent+1) + str(defs[i]))
    print("    "*indent + "}")

class cythonHelper():
    def __init__(self):
        self.curPrg = currentProgram()
        # self.initLogfile()
        self.fm = self.curPrg.getFunctionManager()
        self.mem = self.curPrg.getMemory()
        self.mod_name = None
        self.create_func = None
        self.exec_func = None
        self.consts_map = {}
        self.initSec()
        self.initModule()
        self.initFromStrtab()
        self.pyx_d_addr = None
        self.pyx_d = None
        self.funcs = []
        self.initFromExec()

    # def __del__(self):
    #     file_pointer.close()

    def getHigh(self, f):
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(self.curPrg)
        ifc.setSimplificationStyle("decompile")
        res = ifc.decompileFunction(f, 0, ConsoleTaskMonitor())
        high = res.getHighFunction()
        return high

    def _printItem(self, x):
        if isinstance(x, Address):
            return str(x)
        elif isinstance(x, type([])):
            x = x.copy()
            for i in range(len(x)):
                x[i] = self._printItem(x[i])
        elif isinstance(x, type({})):
            x = x.copy()
            for k, v in x.items():
                x[k] = self._printItem(v)
        return x

    def _createData(self, addr, data_type):
        try:
            createData(addr, data_type)
        except RuntimeError:
            try:
                removeDataAt(addr)
                createData(addr, data_type)
            except RuntimeError:
                pass
        return

    def _chgAdspc(self, addr, before, after):
        return toAddr(str(addr).replace(before, after))

    def _getAdspc(self, addr):
        if addr:
            return addr.getAddressSpace().getName()

    def _getVarAdspc(self, v):
        return self._getAdspc(v.getAddress())

    def _ptr2addr(self, ptr):
        return toAddr(getLong(ptr))

    def _addr2str(self, addr, length=None):
        self._createData(addr, StringDataType())
        if length:
            return bytes(list(getBytes(addr, length-1))).decode()
        else: # null terminated ascii string
            rslt = ""
            if addr.getOffset() != 0:
                while b:=getByte(addr):
                    rslt += chr(b)
                    addr = addr.add(1)
            return rslt

    def _addr2const(self, addr):
        assert self._getAdspc(addr) == CONST
        ram_addr = self._chgAdspc(addr, CONST, RAM)
        try: # TODO: Arbitrary judgment T^T
            getByte(ram_addr)
            # WARNING(f"check if Address {addr} is really a memory address?")
        except Exception as e:
            if "does not exist in memory" in str(e):
                return addr
        return ram_addr

    def _getOpDef(self, op):
        rslt = [self._getDef(op.getOutput(), False), op.getOpcode()]
        for x in op.getInputs():
            rslt.append(self._getDef(x))
        return rslt

    def _getDef(self, v, isinp=True):
        if not v:
            return None
        addr_space = self._getVarAdspc(v)
        if addr_space == RAM:
            return v.getAddress()
        elif addr_space == CONST:
            return self._addr2const(v.getAddress())
        ### parse input
        if isinp and (op:=v.getDef()):
            opc = op.getOpcode()
            if opc in [PcodeOp.CAST, PcodeOp.COPY]:
                return self._getDef(op.getInput(0))
            elif opc == PcodeOp.MULTIEQUAL:
                for x in op.getInputs():
                    if x != v:
                        return self._getDef(x)
            else:
                return [self._getDef(v, False), opc] + [self._getDef(x) for x in op.getInputs()]
        ### parse output
        elif not isinp:
            op_iter = v.getDescendants()
            while op_iter.hasNext():
                op = op_iter.next()
                if op.getOutput():
                    opc = op.getOpcode()
                    if opc in [PcodeOp.CAST, PcodeOp.COPY, PcodeOp.INDIRECT]:
                        return self._getDef(op.getOutput(), False)
            else:
                return v.getAddress()
        ### if cannot find
        return v.getAddress()

    def _getContentFromAddr(self, addr, data_type=None):
        addr_space = self._getAdspc(addr)
        if addr in self.consts_map.keys():
            return self.consts_map[addr]
        elif addr_space == CONST:
            return self._addr2const(addr)
        elif self.data_block.contains(addr) or self.rodata_block.contains(addr):
            if data_type == TYPE_STR:
                rslt = self._addr2str(addr)
            elif data_type == TYPE_INT:
                rslt = getInt(addr)
            elif data_type == TYPE_MDEF:
                self._createData(addr, PointerDataType(StringDataType(), 8)) # ml_name
                self._createData(addr.add(8), PointerDataType()) # ml_meth
                self._createData(addr.add(8+8), IntegerDataType()) # ml_flags
                self._createData(addr.add(8+8+8), PointerDataType(StringDataType(), 8)) # ml_doc
                rslt = {
                    "ml_name": self._getContentFromDef(self._ptr2addr(addr), TYPE_STR),
                    "ml_meth": self._ptr2addr(addr.add(8)),
                    "ml_flags": self._getContentFromDef(addr.add(8+8), TYPE_INT),
                    "ml_doc": self._getContentFromDef(self._ptr2addr(addr.add(8+8+8)), TYPE_STR)
                }
            else:
                WARNING(f"have no data_type when parsing {addr}")
                return None
            return rslt
        elif self.bss_block.contains(addr):
            return addr
        elif self._getAdspc(addr) == STACK:
            return addr
        if data_type != 0xdeadbeef and not addr.equals(toAddr(0)):
            WARNING(f"Unexcepted {data_type}:{addr}")
        return None

    def _getContentFromDef(self, defs, data_type=None):
        if isinstance(defs, Address):
            return self._getContentFromAddr(defs, data_type)
        elif (ret:=self._getValFromDef(defs)):
            if isinstance(ret, Address):
                return self._getContentFromAddr(ret, data_type)
            else:
                return ret
        else:
            return None

    def _getValFromDef(self, defs):
        '''
        defs = [op.getOutput(), op.getOpcode(), op.getInput(0), op.getInput(1), op.getInput(2), ...]
        > _getDef(op.getOutput(), False)
        > _getDef(op.getInput(i))
        '''
        if not isinstance(defs, type([])):
            return defs
        # in case of some functions is used to define args
        for x in defs:
            if FLAG_DST in str(x):
                # printDef(defs)
                WARNING(f"get DST in {str(defs)[:32]}")
        output = defs[0]
        opc = defs[1]
        ### PTRSUB: output = input0 + input1
        if opc == PcodeOp.PTRSUB:
            addr1 = self._getValFromDef(defs[2])
            addr2 = self._getValFromDef(defs[3])
            if (r:=self.curPrg.getRegister(addr1)) and "RSP" in r.getName():
                return self._chgAdspc(addr2, CONST, STACK)
            else:
                return self._chgAdspc(addr1.add(addr2.getOffset()), CONST, RAM)
        ### COPY: output = input0
        elif opc == PcodeOp.COPY:
            return self._getValFromDef(defs[2])
        ### CALL
        elif opc == PcodeOp.CALL:
            callee = getFunctionAt(defs[2]).getName()
            assert callee
            ## get pyx_d
            if not self.pyx_d_addr and "PyModule_GetDict" in callee:
                self.pyx_d_addr = output
                createLabel(self.pyx_d_addr, "__pyx_d", True)
                self.consts_map.update({self.pyx_d_addr: {}})
                self.pyx_d = self.consts_map[self.pyx_d_addr]
                return
            if callee.startswith("PyLong_From"):
                addr = output
                if callee == "PyLong_FromString":
                    ## PyLong_FromString(const char *str, char **pend, int base)
                    # cython usually input 0 to pend and base
                    assert self._getContentFromDef(defs[4]).getOffset() == 0 and self._getContentFromDef(defs[5]).getOffset() == 0
                    s = self._getContentFromDef(defs[3], TYPE_STR)
                    base = 10 # default
                    if s[:2] in ["0x", "0X"]:
                        base = 16
                    elif s[:2] in ["0o", "0O"]:
                        base = 8
                    elif s[:2] in ["0b", "0B"]:
                        base = 2
                    long = int(s, base)
                else:
                    long = self._getContentFromDef(defs[3]).getOffset()
                new_label = NUM_fmt.format(long)
                self.consts_map.update({addr: long})
                createLabel(addr, new_label, True)
            elif callee == "PyTuple_Pack":
                addr = output
                size = self._getContentFromDef(defs[3]).getOffset()
                rslt = []
                new_label = TUPLE_fmt.format(size)
                for i in range(size):
                    item = self._getContentFromDef(defs[4+i])
                    rslt.append(item)
                    new_label += f"_{item}"
                rslt = tuple(rslt)
                self.consts_map.update({addr: rslt})
                createLabel(addr, new_label, True)
                return rslt
            elif callee == "PyCode_NewWithPosOnlyArgs":
                ## Varies with version, 3.10 for now
                # https://github.com/python/cpython/blob/3.10/Objects/codeobject.c#L117
                # PyCode_NewWithPosOnlyArgs(int argcount, int posonlyargcount, int kwonlyargcount, int nlocals, int stacksize, int flags,
                #                           PyObject *code, PyObject *consts, PyObject *names, PyObject *varnames, PyObject *freevars, PyObject *cellvars, PyObject *filename, PyObject *name,
                #                           int firstlineno, PyObject *linetable)
                addr = output
                rslt = {}
                tmp = []
                for i in range(6):
                    tmp.append(self._getContentFromDef(defs[3+i]).getOffset())
                rslt.update(dict(zip(["argcount", "posonlyargcount", "kwonlyargcount", "nlocals", "stacksize", "flags"], tmp)))
                tmp = []
                for i in range(8):
                    tmp.append(self._getContentFromDef(defs[9+i]))
                rslt.update(dict(zip(["code", "consts", "names", "varnames", "freevars", "cellvars", "filename", "name"], tmp)))
                rslt.update({"firstlineno": self._getContentFromDef(defs[17]).getOffset()})
                rslt.update({"linetable": self._getContentFromDef(defs[18])})
                self.consts_map.update({addr: rslt})
                new_label = CODE_fmt.format(rslt["name"])
                createLabel(addr, new_label, True)
            elif callee == "PyDict_SetItem":
                d = self._getContentFromDef(defs[3])
                k = self._getContentFromDef(defs[4])
                v = self._getContentFromDef(defs[5])
                d[k] = v
                if d == self.pyx_d:
                    LOG(f"{k} = {self._printItem(v)}")
            elif "Pyx_CyFunction_New" in callee:
                # Pyx_CyFunction_New(module_def, qualname, mname, code)
                mdef = self._getContentFromDef(defs[3], TYPE_MDEF)
                qname = self._getContentFromDef(defs[4], TYPE_STR)
                mname = self._getContentFromDef(defs[5], TYPE_STR)
                code = self._getContentFromDef(defs[7])
                d = {"mdef": mdef, "qualname": qname, "module": mname, "code": code}
                self.funcs.append(d)
                return d
            elif callee == "PyImport_AddModule":
                addr = output
                string = self._getContentFromDef(defs[3], TYPE_STR)
                self.consts_map.update({addr: string})
                new_label = MOD_fmt.format(string)
                createLabel(addr, new_label, True)
                LOG(f"import {string}")
            elif callee == "PyTuple_New":
                addr = output
                size = self._getContentFromDef(defs[3]).getOffset()
                self.consts_map.update({addr: tuple([None for _ in range(size)])})
                new_label = TUPLE_fmt.format(size)
                createLabel(addr, new_label, True)
            elif callee in ["PyBytes_FromStringAndSize", "PyUnicode_FromStringAndSize"]:
                addr = output
                size = self._getContentFromDef(defs[4]).getOffset()
                string = self._addr2str(defs[3], size)
                self.consts_map.update({addr: string})
                new_label = BYTE_fmt.format(string)
                createLabel(addr, new_label, True)
            elif callee == "PyList_New":
                size = self._getContentFromDef(defs[3]).getOffset()
                return f"[{size} items]"
            elif callee == "__Pyx_GetBuiltinName":
                return self._getContentFromDef(defs[3])
            elif "CallDict" in callee:
                f = self._getContentFromDef(defs[3])
                arg = self._getContentFromDef(defs[4])
                LOG(f"{f}({arg})")
            elif "PyDict_New" in callee:
                pass
            else:
                printDef(defs)
                WARNING(f"Unexcepted callee")
            return
        else:
            print("?opcode:", defs)
            return

    # def initLogfile(self):
    #     exec_path = path.split(self.curPrg.getExecutablePath())
    #     log_path = path.join(exec_path[0], f"{exec_path[1]}.log")
    #     global file_pointer
    #     file_pointer = open(log_path, "w")
    #     INFO(f"Log outputs at {log_path}")
    #     return

    def initSec(self):
        # get .data / .rodata / .bss
        self.data_block = None
        self.rodata_block = None
        self.bss_block = None
        for x in self.mem.getBlocks():
            if not self.data_block and x.getName() == ".data":
                self.data_block = x
            elif not self.rodata_block and x.getName() == ".rodata":
                self.rodata_block = x
            elif not self.bss_block and x.getName() == ".bss":
                self.bss_block = x
            elif self.data_block and self.rodata_block and self.bss_block:
                INFO(f"Get {self.data_block}, {self.rodata_block}, {self.bss_block}")
                break
        else:
            ERROR(f"Get {self.data_block}, {self.rodata_block}, {self.bss_block}")
        return

    def initModule(self):
        INIT_TAG = "PyInit_"
        INIT_FUNC = "PyModuleDef_Init"
        ### find PyModuleDef_Init
        f_iter = self.fm.getFunctionsNoStubs(True)
        while f_iter.hasNext():
            # A module's start must be "PyInit_{MOD_NAME}"
            if (f:=f_iter.next()).getName().startswith(INIT_TAG):
                self.mod_name = f.getName()[len(INIT_TAG):]
                INFO(f"Module name: {self.mod_name}")
                break
        else:
            ERROR(f"Failed to find {INIT_TAG}* function.")
        ### get __pyx_moduledef from PyModuleDef_Init's input
        op_iter = self.getHigh(f).getPcodeOps()
        while op_iter.hasNext():
            op = op_iter.next()
            if op.getOpcode() == PcodeOp.CALL:
                assert INIT_FUNC == getFunctionAt(op.getInput(0).getAddress()).getName()
                mod_def = self._getValFromDef(self._getDef(op.getInput(1)))
                INFO(f"Get __pyx_moduledef addr: {mod_def}")
                break
        else:
            ERROR("Failed to find __pyx_moduledef.")
        ### parse __pyx_moduledef
        # get PyModuleDef's size from https://github.com/python/cpython/blob/3.10/Include/moduleobject.h#L75
        # unused datatype has not been created: m_traverse, m_clear, m_free
        self._createData(mod_def, ArrayDataType(LongDataType(), 5, 8)) # m_base
        self._createData(mod_def.add(40), PointerDataType(StringDataType(), 8)) # m_name
        self._createData(mod_def.add(40+8*1), PointerDataType(StringDataType(), 8)) # m_doc
        self._createData(mod_def.add(40+8*2), LongDataType()) # m_size
        self._createData(mod_def.add(40+8*3), PointerDataType()) # m_methods
        self._createData(mod_def.add(40+8*4), PointerDataType()) # m_slots
        ### parse __pyx_moduledef_slots
        # get PyModuleDef_Slot's size from https://github.com/python/cpython/blob/3.10/Include/moduleobject.h#L61
        PyModuleDef_Slot = StructureDataType("PyModuleDef_Slot", 12)
        PyModuleDef_Slot.insertAtOffset(0, IntegerDataType(), 0)
        PyModuleDef_Slot.insertAtOffset(8, PointerDataType(), 0) # align
        [PyModuleDef_Slot.deleteAtOffset(16) for _ in range(4)]
        mod_def_slots = toAddr(getLong(mod_def.add(40+8*4)))
        self._createData(mod_def_slots, ArrayDataType(PyModuleDef_Slot, 3, 16))
        for i in range(0, 32, 16):
            slot = getInt(mod_def_slots.add(i))
            value = getLong(mod_def_slots.add(i+8))
            assert slot in [1, 2]
            if slot == 1: # Py_mod_create
                self.create_func = getFunctionAt(toAddr(value))
            else: # Py_mod_exec
                self.exec_func = getFunctionAt(toAddr(value))
        INFO(f"Get (Py_mod_create){self.create_func.getName()} addr: {self.create_func.getEntryPoint()}")
        INFO(f"Get (Py_mod_exec){self.exec_func.getName()} addr: {self.exec_func.getEntryPoint()}")
        return

    def initFromStrtab(self):
        f = getGlobalFunctions("__Pyx_CreateStringTabAndInitStrings")[0]
        op_iter = self.getHigh(f).getPcodeOps()
        strtab_sz = 0x28
        sp = None
        while op_iter.hasNext():
            op = op_iter.next()
            if not sp and op.getOutput().isRegister() and "RSP" in self.curPrg.getRegister(op.getOutput()).getName():
                sp = self._chgAdspc(op.getInput(1).getAddress(), CONST, STACK)
                stack_sz = -sp.getOffset()
                tmp_consts = [{"addr": None, "str": None, "len": None} for _ in range(stack_sz)]
                continue
            if not sp:
                continue
            if (outputAddr:=op.getOutput().getAddress()).isStackAddress():
                offset = outputAddr.subtract(sp)
                b, boff = offset // strtab_sz, offset % strtab_sz
                defs = self._getDef(op.getOutput())
                if boff == 0x0 and not tmp_consts[b]["addr"]:
                    tmp_consts[b]["addr"] = self._getContentFromDef(defs)
                elif boff == 0x8 and not tmp_consts[b]["str"]:
                    tmp_consts[b]["str"] = self._getContentFromDef(defs, TYPE_STR)
                elif boff == 0x10 and not tmp_consts[b]["len"]:
                    tmp_consts[b]["len"] = self._getContentFromDef(defs).getOffset()
                else:
                    continue
                if None not in tmp_consts[b].values():
                    addr = tmp_consts[b]["addr"]
                    string = tmp_consts[b]["str"]
                    length = tmp_consts[b]["len"]
                    new_label = STR_fmt.format(string)
                    self.consts_map.update({addr: string})
                    # rename
                    createLabel(addr, new_label, True)
                    # complete?
                    if len(self.consts_map) == len(tmp_consts)//strtab_sz - 1:
                        break
        INFO('Get StringTabs from "__Pyx_StringTabEntry".')
        return

    def initFromExec(self):
        f = self.exec_func
        op_iter = self.getHigh(f).getPcodeOps()
        while op_iter.hasNext():
            op = op_iter.next()
            if op.getOpcode() == PcodeOp.CALL:
                if self._getAdspc(self._getDef(op.getOutput(), False)) in [RAM, CONST] or getFunctionAt(op.getInput(0).getAddress()).getName() in ["PyDict_SetItem"]:
                    self._getContentFromDef(self._getOpDef(op))
        INFO("Rename vars completed.")
        return


if __name__ == '__main__':
    ch = cythonHelper()
