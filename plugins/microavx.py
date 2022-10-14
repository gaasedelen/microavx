import sys

import idc
import ida_ua
import ida_ida
import ida_idp
import ida_funcs
import ida_allins
import ida_idaapi
import ida_loader
import ida_kernwin
import ida_typeinf
import ida_hexrays
import traceback

#-----------------------------------------------------------------------------
# Util
#-----------------------------------------------------------------------------

# an empty / NULL mop_t
NO_MOP = None

# EVEX-encoded instruction, intel.hpp (ida sdk)
AUX_EVEX = 0x10000

# register widths (bytes)
XMM_SIZE = 16
YMM_SIZE = 32
ZMM_SIZE = 64

# type sizes (bytes)
FLOAT_SIZE = 4
DOUBLE_SIZE = 8
DWORD_SIZE = 4
QWORD_SIZE = 8

R_ax = 0
R_r15 = 15

def size_of_operand(op):
    """
    From ...
        https://reverseengineering.stackexchange.com/questions/19843/how-can-i-get-the-byte-size-of-an-operand-in-ida-pro
    """
    tbyte = 8
    dt_ldbl = 8
    n_bytes = [ 1, 2, 4, 4, 8,
            tbyte, -1, 8, 16, -1,
            -1, 6, -1, 4, 4,
            dt_ldbl, 32, 64 ]
    return n_bytes[op.dtype]

def is_amd64_idb():
    """
    Return true if an x86_64 IDB is open.
    """
    if ida_idp.ph.id != ida_idp.PLFM_386:
        return False
    return ida_ida.cvar.inf.is_64bit()

def bytes2bits(n):
    """
    Return the number of bits repersented by 'n' bytes.
    """
    return n * 8

def is_mem_op(op):
    """
    Return true if the given operand *looks* like a mem op.
    """
    return op.type in [ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_phrase]

def is_reg_op(op):
    """
    Return true if the given operand is a register.
    """
    return op.type in [ida_ua.o_reg]

def is_avx_reg(op):
    """
    Return true if the given operand is a XMM or YMM register.
    """
    return bool(is_xmm_reg(op) or is_ymm_reg(op))

def is_xmm_reg(op):
    """
    Return true if the given operand is a XMM register.
    """
    if op.type != ida_ua.o_reg:
        return False
    if op.dtype != ida_ua.dt_byte16:
        return False
    return True

def is_ymm_reg(op):
    """
    Return true if the given operand is a YMM register.
    """
    if op.type != ida_ua.o_reg:
        return False
    if op.dtype != ida_ua.dt_byte32:
        return False
    return True

def is_avx_512(insn):
    """
    Return true if the given insn_t is an AVX512 instruction.
    """
    return bool(insn.auxpref & AUX_EVEX)

def is_gpr32(op):
    return op.type == ida_ua.o_reg and op.dtype == ida_ua.dt_dword and R_ax <= op.reg <= R_di

def is_gpr64(op):
    return op.type == ida_ua.o_reg and op.dtype == ida_ua.dt_qword and R_ax <= op.reg <= R_r15

def is_gpr(op):
    return is_gpr32(op) or is_gpr64(op)

#-----------------------------------------------------------------------------
# Microcode Helpers
#-----------------------------------------------------------------------------

def get_ymm_mreg(xmm_mreg):
    """
    Return the YMM microcode register for a given XMM register.
    """
    xmm_reg = ida_hexrays.mreg2reg(xmm_mreg, XMM_SIZE)
    xmm_name = ida_idp.get_reg_name(xmm_reg, XMM_SIZE)
    xmm_number = int(xmm_name.split("mm")[-1])

    # compute the ymm mreg id
    ymm_reg = ida_idp.str2reg("ymm%u" % xmm_number)
    ymm_mreg = ida_hexrays.reg2mreg(ymm_reg)

    # sanity check...
    xmm_name = ida_hexrays.get_mreg_name(xmm_mreg, XMM_SIZE)
    ymm_name = ida_hexrays.get_mreg_name(ymm_mreg, YMM_SIZE)
    assert xmm_name[1:] == ymm_name[1:], "Reg escalation did not work... (%s, %s)" % (xmm_name, ymm_name)
 
    # return the ymm microcode register id
    return ymm_mreg

def clear_upper(cdg, xmm_mreg, op_size=XMM_SIZE):
    """
    Extend the given xmm reg, clearing the upper bits (through ymm).
    """
    ymm_mreg = get_ymm_mreg(xmm_mreg)

    xmm_mop = ida_hexrays.mop_t(xmm_mreg, op_size)
    ymm_mop = ida_hexrays.mop_t(ymm_mreg, YMM_SIZE)

    return cdg.emit(ida_hexrays.m_xdu, xmm_mop, NO_MOP, ymm_mop)

def store_operand_hack(cdg, op_num, new_mop):
    """
    XXX: why is there a load_operand(), but no inverse.. ?
    """

    # emit a 'load' operation...
    memX = cdg.load_operand(op_num)
    assert memX != ida_hexrays.mr_none, "Invalid op_num..."

    # since this is gonna be kind of hacky, let's make sure a load was actually emitted
    ins = cdg.mb.tail
    if ins.opcode != ida_hexrays.m_ldx:
        if ins.prev.opcode != ida_hexrays.m_ldx:
            raise ValueError("Hehe, hack failed :-( (insn 0x%08X op 0x%02X)" % (cdg.insn.ea, ins.opcode))
        prev = ins.prev
        cdg.mb.make_nop(ins)
        ins = prev
    assert ins.d.size == new_mop.size, "%u vs %u" % (new_mop.size, ins.d.size)

    # convert the load to a store :^)
    ins.opcode = ida_hexrays.m_stx
    ins.d = ins.r   # d = op mem offset
    ins.r = ins.l   # r = op mem segm 
    ins.l = new_mop # l = value to store (mop_t)

    return ins

#-----------------------------------------------------------------------------
# Intrinsic Helper
#-----------------------------------------------------------------------------

class AVXIntrinsic(object):
    """
    This class helps with generating simple intrinsic calls in microcode.
    """

    def __init__(self, cdg, name):
        self.cdg = cdg

        # call info, sort of like func_type_data_t()
        self.call_info = ida_hexrays.mcallinfo_t()
        self.call_info.cc = ida_typeinf.CM_CC_FASTCALL
        self.call_info.callee = ida_idaapi.BADADDR
        self.call_info.solid_args = 0
        self.call_info.role = ida_hexrays.ROLE_UNK
        self.call_info.flags = ida_hexrays.FCI_SPLOK | ida_hexrays.FCI_FINAL | ida_hexrays.FCI_PROP

        # the actual 'call' microcode insn
        self.call_insn = ida_hexrays.minsn_t(cdg.insn.ea)
        self.call_insn.opcode = ida_hexrays.m_call
        self.call_insn.l.make_helper(name)
        self.call_insn.d.t = ida_hexrays.mop_f
        self.call_insn.d.f = self.call_info

        # temp return type
        self.call_info.return_type = ida_typeinf.tinfo_t()
        self.call_insn.d.size = 0

    def set_return_reg(self, mreg, type_string):
        """
        Set the return register of the function call, with a type string.
        """
        ret_tinfo = ida_typeinf.tinfo_t()
        ret_tinfo.get_named_type(None, type_string)
        return self.set_return_reg_type(mreg, ret_tinfo)

    def set_return_reg_basic(self, mreg, basic_type):
        """
        Set the return register of the function call, with a basic type assigned.
        """
        ret_tinfo = ida_typeinf.tinfo_t(basic_type)
        return self.set_return_reg_type(mreg, ret_tinfo)

    def set_return_reg_type(self, mreg, ret_tinfo):
        """
        Set the return register of the function call, with a complex type.
        """
        self.call_info.return_type = ret_tinfo
        self.call_insn.d.size = ret_tinfo.get_size()

        self.mov_insn = ida_hexrays.minsn_t(self.cdg.insn.ea)
        self.mov_insn.opcode = ida_hexrays.m_mov
        self.mov_insn.l.t = ida_hexrays.mop_d
        self.mov_insn.l.d = self.call_insn
        self.mov_insn.l.size = self.call_insn.d.size
        self.mov_insn.d.t = ida_hexrays.mop_r
        self.mov_insn.d.r = mreg
        self.mov_insn.d.size = self.call_insn.d.size

        if ret_tinfo.is_decl_floating():
            self.mov_insn.set_fpinsn()

    def add_argument_reg(self, mreg, type_string):
        """
        Add a regeister argument with a given type string to the function argument list.
        """
        op_tinfo = ida_typeinf.tinfo_t()
        op_tinfo.get_named_type(None, type_string)
        return self.add_argument_reg_type(mreg, op_tinfo)

    def add_argument_reg_basic(self, mreg, basic_type):
        """
        Add a regeister argument with a basic type to the function argument list.
        """
        op_tinfo = ida_typeinf.tinfo_t(basic_type)
        return self.add_argument_reg_type(mreg, op_tinfo)

    def add_argument_reg_type(self, mreg, op_tinfo):
        """
        Add a register argument of the given type to the function argument list.
        """
        call_arg = ida_hexrays.mcallarg_t()
        call_arg.t = ida_hexrays.mop_r
        call_arg.r = mreg
        call_arg.type = op_tinfo
        call_arg.size = op_tinfo.get_size()

        self.call_info.args.push_back(call_arg)
        self.call_info.solid_args += 1

    def add_argument_imm(self, value, basic_type):
        """
        Add an immediate value to the function argument list.
        """
        op_tinfo = ida_typeinf.tinfo_t(basic_type)

        mop_imm = ida_hexrays.mop_t()
        mop_imm.make_number(value, op_tinfo.get_size())
        
        call_arg = ida_hexrays.mcallarg_t()
        call_arg.make_number(value, op_tinfo.get_size())
        call_arg.type = op_tinfo

        self.call_info.args.push_back(call_arg)
        self.call_info.solid_args += 1

    def emit(self):
        """
        Emit the intrinsic call to the generated microcode.
        """
        self.cdg.mb.insert_into_block(self.mov_insn, self.cdg.mb.tail)


class garbage_remover_t(ida_hexrays.minsn_visitor_t):
    """
    remove duplicate instructions introduced by store_operand_hack?
    """
    def __init__(self, ea):
        ida_hexrays.minsn_visitor_t.__init__(self)
        self.addr = ea
        self.insns = []

    def visit_minsn(self):
        ins = self.curins

        if ins.ea == self.addr:
            self.insns.append(ins)
        return 0

#-----------------------------------------------------------------------------
# AVX Lifter
#-----------------------------------------------------------------------------

class AVXLifter(ida_hexrays.microcode_filter_t):
    """
    A Hex-Rays microcode filter to lift AVX instructions during decompilation.
    """

    def __init__(self):
        super(AVXLifter, self).__init__()
        self.cdg = None
        self._avx_handlers = \
        {

            # Compares (Scalar, Single / Double-Precision)
            ida_allins.NN_vcomiss: self.vcomiss,
            ida_allins.NN_vcomisd: self.vcomisd,
            ida_allins.NN_vucomiss: self.vucomiss,
            ida_allins.NN_vucomisd: self.vucomisd,

            # Conversions
            ida_allins.NN_vcvttss2si: self.vcvttss2si,
            ida_allins.NN_vcvttsd2si: self.vcvttsd2si,
            ida_allins.NN_vcvtdq2ps: self.vcvtdq2ps,
            ida_allins.NN_vcvtsi2ss: self.vcvtsi2ss,
            ida_allins.NN_vcvtsi2sd: self.vcvtsi2sd,
            ida_allins.NN_vcvtps2pd: self.vcvtps2pd,
            ida_allins.NN_vcvtss2sd: self.vcvtss2sd,
            ida_allins.NN_vcvtsd2ss: self.vcvtsd2ss,

            # Mov (DWORD / QWORD)
            ida_allins.NN_vmovd: self.vmovd,
            ida_allins.NN_vmovq: self.vmovq,

            # Mov (Scalar, Single / Double-Precision)
            ida_allins.NN_vmovss: self.vmovss,
            ida_allins.NN_vmovsd: self.vmovsd,

            # Mov (Packed Single-Precision, Packed Integers)
            ida_allins.NN_vmovaps: self.v_mov_ps_dq,
            ida_allins.NN_vmovups: self.v_mov_ps_dq,
            ida_allins.NN_vmovdqa: self.v_mov_ps_dq,
            ida_allins.NN_vmovdqu: self.v_mov_ps_dq,

            ida_allins.NN_vmovupd: self.v_mov_ps_dq,
            ida_allins.NN_vmovapd: self.v_mov_ps_dq,

            # Bitwise (Packed Single-Precision)
            ida_allins.NN_vorps: self.v_bitwise_ps,
            ida_allins.NN_vandps: self.v_bitwise_ps,
            ida_allins.NN_vandpd: self.v_bitwise_ps,
            ida_allins.NN_vxorps: self.v_bitwise_ps,
            ida_allins.NN_vxorpd: self.v_bitwise_ps,

            # Math (Scalar Single-Precision)
            ida_allins.NN_vaddss: self.v_math_ss,
            ida_allins.NN_vsubss: self.v_math_ss,
            ida_allins.NN_vmulss: self.v_math_ss,
            ida_allins.NN_vdivss: self.v_math_ss,

            # Math (Scalar Double-Precision)
            ida_allins.NN_vaddsd: self.v_math_sd,
            ida_allins.NN_vsubsd: self.v_math_sd,
            ida_allins.NN_vmulsd: self.v_math_sd,
            ida_allins.NN_vdivsd: self.v_math_sd,

            # Math (Packed Single-Precision)
            ida_allins.NN_vaddps: self.v_math_ps,
            ida_allins.NN_vsubps: self.v_math_ps,
            ida_allins.NN_vmulps: self.v_math_ps,
            ida_allins.NN_vdivps: self.v_math_ps,

            ida_allins.NN_vaddpd: self.v_math_ps,
            ida_allins.NN_vsubpd: self.v_math_ps,
            ida_allins.NN_vmulpd: self.v_math_ps,

            # Square Root
            ida_allins.NN_vsqrtss: self.vsqrtss,
            ida_allins.NN_vsqrtps: self.vsqrtps,

            # Shuffle (Packed Single-Precision) 
            ida_allins.NN_vshufps: self.vshufps,

            ida_allins.NN_vfmadd132sd: self.vfmadd132sd,
            ida_allins.NN_vfmadd213sd: self.vfmadd213sd,
            ida_allins.NN_vfmadd231sd: self.vfmadd231sd,
            ida_allins.NN_vfnmadd132sd: self.vfnmadd132sd,
            ida_allins.NN_vfnmadd213sd: self.vfnmadd213sd,
            ida_allins.NN_vfnmadd231sd: self.vfnmadd231sd,
            ida_allins.NN_vmaxsd: self.vmaxsd,
            ida_allins.NN_vminsd: self.vminsd,
            ida_allins.NN_vpxor: self.vpxor,
            ida_allins.NN_vfmsub132sd: self.vfmsub132sd,
            ida_allins.NN_vfmsub213sd: self.vfmsub213sd,
            ida_allins.NN_vfmsub231sd: self.vfmsub231sd,
            ida_allins.NN_vroundsd: self.vroundsd,

            #vblendvpd
            #vfmadd231pd
            #vcmpnltsd

            #vsqrtsd
            #vunpckhpd
            #vextractf128
            #vpermilpd
            #vperm2f128
            #vblendpd
        }

    def match(self, cdg):
        """
        Return true if the lifter supports this AVX instruction.
        """
        if is_avx_512(cdg.insn):
            return False
        return cdg.insn.itype in self._avx_handlers

    def remove_store_operand_hack_dupinstrs(self, cdg, insn):
        gc = garbage_remover_t(insn.ea)
        cdg.mb.for_all_insns(gc)
        if len(gc.insns) >= 1:
            print(f'found {len(gc.insns)} duplicate microcode instructions for {insn.ea:x} ')
            for instr in gc.insns:
                cdg.mb.remove_from_block(instr)

    def apply(self, cdg):
        """
        Generate microcode for the current instruction.
        """
        try:
            cdg.store_operand = lambda x, y: store_operand_hack(cdg, x, y)
            self.remove_store_operand_hack_dupinstrs(cdg, cdg.insn)
            self.cdg = cdg
            result = self._avx_handlers[cdg.insn.itype](cdg, cdg.insn)
            self.cdg = None
            return result
        except Exception as err:
            print(f'addr = {cdg.insn.ea:x}, x  = {traceback.format_exc()}')
            return ida_hexrays.MERR_INSN

    def install(self):
        """
        Install the AVX codegen lifter.
        """
        ida_hexrays.install_microcode_filter(self, True)
        print("Installed AVX lifter... (%u instr supported)" % len(self._avx_handlers))

    def remove(self):
        """
        Remove the AVX codegen lifter.
        """
        ida_hexrays.install_microcode_filter(self, False)
        print("Removed AVX lifter...")

    def decode_error(self, msg):
        print(f'{self.cdg.insn.ea:x}: {msg}')
        return ida_hexrays.MERR_INSN

    def xmmreg(self, op):
        if is_xmm_reg(op):
            result = ida_hexrays.reg2mreg(op.reg)
        else:
            result = None
        return result

    def xmm_or_mem(self, op):
        if is_xmm_reg(op):
            result = ida_hexrays.reg2mreg(op.reg)
        elif is_mem_op(op):
            result = self.cdg.load_operand(op.n)
        else:
            result = None
        return result

    def xmm1_xmm2_or_mem2(self):
        result = None
        insn = self.cdg.insn
        s = self.xmm_or_mem(insn.Op2)
        if s is not None:
            d = self.xmmreg(insn.Op1)
            if d is not None:
                result = (d, s)
            else:
                self.decode_error('op1')
        else:
            self.decode_error('op2')
        return result

    def xmm1_xmm2_xmm3_or_mem3(self):
        result = None
        insn = self.cdg.insn
        c = self.xmm_or_mem(insn.Op3)
        if c is not None:
            b = self.xmmreg(insn.Op2)
            if b is not None:
                a = self.xmmreg(insn.Op1)
                if a is not None:
                    result = (a, b, c)
                else:
                    self.decode_error('op1')
            else:
                self.decode_error('op2')
        else:
            self.decode_error('op3')
        return result

    def save_upper_bits(self, mreg, reg_size):
        # create a temp register to compute the final result into
        treg = self.cdg.mba.alloc_kreg(reg_size)

        # populate the dest reg
        self.cdg.emit(ida_hexrays.m_mov, reg_size, mreg, 0, treg, 0)
        return treg

    def alloc_reg(self, reg_size):
        return self.cdg.mba.alloc_kreg(reg_size)

    def free_reg(self, reg, reg_size):
        self.cdg.mba.free_kreg(reg, reg_size)

    def emit_fp_instr_l_r_d(self, opcode, l, r, d):
        instr = ida_hexrays.minsn_t(self.cdg.insn.ea)
        instr.opcode = opcode
        instr.l = l
        instr.r = r
        instr.d = d
        instr.set_fpinsn()
        self.cdg.mb.insert_into_block(instr, self.cdg.mb.tail)

    def emit_fp_instr_l_d(self, opcode, l, d):
        instr = ida_hexrays.minsn_t(self.cdg.insn.ea)
        instr.opcode = opcode
        instr.l = l
        instr.r.zero()
        instr.d = d
        instr.set_fpinsn()
        self.cdg.mb.insert_into_block(instr, self.cdg.mb.tail)

    def emit_clear_dst(self, d):
        nil = ida_hexrays.mop_t()
        nil.make_number(0, d.size)
        instr = ida_hexrays.minsn_t(self.cdg.insn.ea)
        instr.opcode = ida_hexrays.m_mov
        instr.l = nil
        instr.r.zero()
        instr.d = d
        self.cdg.mb.insert_into_block(instr, self.cdg.mb.tail)

    def emit_clear_ymm(self, xmm_mreg):
        #nil = ida_hexrays.mop_t()
        #nil.make_number(0, YMM_SIZE)
        t = self.alloc_reg(YMM_SIZE)
        t_mop = ida_hexrays.mop_t(t, YMM_SIZE)

        xmm_mop = ida_hexrays.mop_t(xmm_mreg, XMM_SIZE)

        ymm_mreg = get_ymm_mreg(xmm_mreg)
        ymm_mop = ida_hexrays.mop_t(ymm_mreg, YMM_SIZE)
        self.cdg.emit(ida_hexrays.m_xdu, xmm_mop, NO_MOP, t_mop)
        self.cdg.emit(ida_hexrays.m_mov, t_mop, NO_MOP, ymm_mop)
        self.free_reg(t, YMM_SIZE)


    def emit_clear_flag(self, mreg):
        self.emit_clear_dst(ida_hexrays.mop_t(mreg, 1))

    def emit_copy_bits_xmm_wide(self, dst, src):
        self.cdg.emit(ida_hexrays.m_mov, ida_hexrays.mop_t(src, XMM_SIZE), NO_MOP, ida_hexrays.mop_t(dst, XMM_SIZE))

    def emit_function_call2(self, r, func_name, p1, p2, is_pure):
        avx_intrinsic = AVXIntrinsic(self.cdg, func_name)
        (reg, typ) = p1
        avx_intrinsic.add_argument_reg_basic(reg, typ)
        (reg, typ) = p2
        avx_intrinsic.add_argument_reg_basic(reg, typ)
        (reg, typ) = r
        avx_intrinsic.set_return_reg_basic(reg, typ)
        if is_pure:
            avx_intrinsic.call_info.flags |= ida_hexrays.FCI_PURE
        avx_intrinsic.emit()

    #--------------------------------------------------------------------------
    # Compare Instructions
    #--------------------------------------------------------------------------

    def v_comis_(self, data_size):
        """
        COMISS (all versions)
        RESULT :=OrderedCompare(DEST[31:0] <> SRC[31:0]) {
        (V)UCOMISS (all versions)
        RESULT := UnorderedCompare(DEST[31:0] <> SRC[31:0]) {
        COMISD (all versions)
        RESULT :=OrderedCompare(DEST[63:0] <> SRC[63:0]) {
        (V)UCOMISD (all versions)
        RESULT := UnorderedCompare(DEST[63:0] <> SRC[63:0]) {

        (* Set EFLAGS *) CASE (RESULT) OF
        UNORDERED: ZF,PF,CF := 111;
        GREATER_THAN: ZF,PF,CF := 000;
        LESS_THAN: ZF,PF,CF := 001;
        EQUAL: ZF,PF,CF := 100;
        ESAC;
        OF, AF, SF := 0; }
        """
        regs = self.xmm1_xmm2_or_mem2()
        if regs is None:
            return ida_hexrays.MERR_INSN

        (l_reg, r_reg) = regs
        L = ida_hexrays.mop_t(l_reg, data_size)
        R = ida_hexrays.mop_t(r_reg, data_size)
        self.emit_function_call2(
            (ida_hexrays.mr_pf, ida_typeinf.BTF_BOOL),
            'std::isunordered',
            (l_reg, ida_typeinf.BTF_DOUBLE),
            (r_reg, ida_typeinf.BTF_DOUBLE),
            True)
        self.emit_fp_instr_l_r_d(ida_hexrays.m_setb, L, R, ida_hexrays.mop_t(ida_hexrays.mr_cf, 1))
        self.emit_fp_instr_l_r_d(ida_hexrays.m_setz, L, R, ida_hexrays.mop_t(ida_hexrays.mr_zf, 1))
        self.emit_clear_flag(ida_hexrays.mr_of)
        #self.emit_clear_flag(ida_hexrays.reg2mreg(R_af))
        self.emit_clear_flag(ida_hexrays.mr_sf)

        return ida_hexrays.MERR_OK

    def vcomiss(self, cdg, insn):
        """
        VCOMISS xmm1, xmm2/m32
        """
        return self.v_comis_(FLOAT_SIZE)

    def vucomiss(self, cdg, insn):
        """
        VUCOMISS xmm1, xmm2/m32
        """
        return self.v_comis_(FLOAT_SIZE)

    def vcomisd(self, cdg, insn):
        """
        VCOMISD xmm1, xmm2/m64
        """
        return self.v_comis_(DOUBLE_SIZE)

    def vucomisd(self, cdg, insn):
        """
        VUCOMISD xmm1, xmm2/m64
        """
        return self.v_comis_(DOUBLE_SIZE)

    #-------------------------------------------------------------------------
    # Conversion Instructions
    #-------------------------------------------------------------------------

    def vcvttss2si(self, cdg, insn):
        """
        CVTTSS2SI r64, xmm1/m32
        CVTTSS2SI r32, xmm1/m32
        """
        insn.itype = ida_allins.NN_cvttss2si
        return ida_hexrays.MERR_INSN

    def vcvttsd2si(self, cdg, insn):
        """
        VCVTTSD2SI r32, xmm1/m64
        VCVTTSD2SI r64, xmm1/m64
        """
        s1 = self.xmm_or_mem(insn.Op2)
        if s1 is None:
            return self.decode_error('op2 - expected xmm reg or mem ptr')

        dst_size = 0
        if is_gpr32(insn.Op1):
            dst_size = 4
        elif is_gpr64(insn.Op1):
            dst_size = 8
        else:
            return self.decode_error('op1 - expected gpr32 or gpr64')

        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        s1_mop = ida_hexrays.mop_t(s1, DOUBLE_SIZE)
        t1 = self.alloc_reg(dst_size)
        t1_mop = ida_hexrays.mop_t(t1, dst_size)
        cdg.emit(ida_hexrays.m_f2i, s1_mop, NO_MOP, t1_mop)
        cdg.emit(ida_hexrays.m_mov, dst_size, t1, 0, d_reg, 0)
        return ida_hexrays.MERR_OK

    def vcvtdq2ps(self, cdg, insn):
        """
        VCVTDQ2PS xmm1, xmm2/m128
        VCVTDQ2PS ymm1, ymm2/m256
        """
        op_size = XMM_SIZE if is_xmm_reg(insn.Op1) else YMM_SIZE

        # op2 -- m128/m256
        if is_mem_op(insn.Op2):
            r_reg = cdg.load_operand(1)

        # op2 -- xmm2/ymm2
        else:
            assert is_avx_reg(insn.Op2)
            r_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        #
        # intrinsics:
        #     __m128 _mm_cvtepi32_ps (__m128i a)
        #     __m256 _mm256_cvtepi32_ps (__m256i a)
        #

        bit_size = bytes2bits(op_size)
        bit_str = str(bit_size) if op_size == YMM_SIZE else ""
        intrinsic_name = "_mm%s_cvtepi32_ps" % bit_str

        avx_intrinsic = AVXIntrinsic(cdg, intrinsic_name)
        avx_intrinsic.add_argument_reg(r_reg, "__m%ui" % bit_size)
        avx_intrinsic.set_return_reg(d_reg, "__m%u" % bit_size)
        avx_intrinsic.emit()

        # clear upper 128 bits of ymm1
        if op_size == XMM_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def _vcvtsi2_ss_sd(self, cdg, insn, dst_size):
        """
        VCVTSI2SS xmm1, xmm2, r/m32
        VCVTSI2SS xmm1, xmm2, r/m64

        VCVTSI2SD xmm1, xmm2, r/m32
        VCVTSI2SD xmm1, xmm2, r/m64
        """
        src2_size = size_of_operand(insn.Op3)

        # op3 -- m32/m64
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- r32/r64
        else:
            assert is_reg_op(insn.Op3)
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)

        # op2 -- xmm2 
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        # create a temp register to compute the final result into
        src1_treg = cdg.mba.alloc_kreg(XMM_SIZE)
        src1_treg_mop_data_size = ida_hexrays.mop_t(src1_treg, dst_size)

        # create a temp register to downcast a double to a float (if needed)
        src2_treg = cdg.mba.alloc_kreg(src2_size)
        src2_treg_mop_src2_size = ida_hexrays.mop_t(src2_treg, src2_size)

        # copy xmm2 into the temp result reg, as we need its upper 3 dwords
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, l_reg, 0, src1_treg, 0)

        # convert the integer (op3) to a float/double depending on its size
        cdg.emit(ida_hexrays.m_i2f, src2_size, r_reg, 0, src2_treg, 0)

        if dst_size != src2_size:
            # reduce precision on the converted floating point value if needed (only r64/m64)
            cdg.emit(ida_hexrays.m_f2f, src2_treg_mop_src2_size, NO_MOP, src1_treg_mop_data_size)
        else:
            cdg.emit(ida_hexrays.m_mov, src2_treg_mop_src2_size, NO_MOP, src1_treg_mop_data_size)

        # transfer the fully computed temp register to the real dest reg 
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, src1_treg, 0, d_reg, 0)
        cdg.mba.free_kreg(src1_treg, XMM_SIZE)
        cdg.mba.free_kreg(src2_treg, src2_size)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vcvtsi2ss(self, cdg, insn):
        return self._vcvtsi2_ss_sd(cdg, insn, FLOAT_SIZE)

    def vcvtsi2sd(self, cdg, insn):
        return self._vcvtsi2_ss_sd(cdg, insn, DOUBLE_SIZE)

    def vcvtps2pd(self, cdg, insn):
        """
        VCVTPS2PD xmm1, xmm2/m64
        VCVTPS2PD ymm1, ymm2/m128
        """
        src_size = QWORD_SIZE if is_xmm_reg(insn.Op1) else XMM_SIZE

        # op2 -- m64/m128
        if is_mem_op(insn.Op2):
            r_reg = cdg.load_operand(1)

        # op2 -- xmm2/ymm2
        else:
            assert is_avx_reg(insn.Op2)
            r_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        #
        # intrinsics:
        #   - __m128d _mm_cvtps_pd (__m128 a)
        #   - __m256d _mm256_cvtps_pd (__m128 a)
        #
  
        bit_size = bytes2bits(src_size * 2)
        bit_str = "256" if (src_size * 2) == YMM_SIZE else ""
        intrinsic_name = "_mm%s_cvtps_pd" % bit_str

        avx_intrinsic = AVXIntrinsic(cdg, intrinsic_name)
        avx_intrinsic.add_argument_reg(r_reg, "__m128")
        avx_intrinsic.set_return_reg(d_reg, "__m%ud" % bit_size)
        avx_intrinsic.emit()
        
        # clear upper 128 bits of ymm1
        if src_size == QWORD_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vcvtss2sd(self, cdg, insn):
        """
        VCVTSS2SD xmm1, xmm2, r/m32
        """

        # op3 -- m32
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- r32
        else:
            assert is_reg_op(insn.Op3)
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)
        
        r_mop = ida_hexrays.mop_t(r_reg, FLOAT_SIZE)

        # op2 -- xmm2 
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        # create a temp register to compute the final result into
        t0_result = cdg.mba.alloc_kreg(XMM_SIZE)
        t0_mop = ida_hexrays.mop_t(t0_result, DOUBLE_SIZE)

        # copy xmm2 into the temp result reg, as we need its upper quadword
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, l_reg, 0, t0_result, 0)

        # convert float (op3) to a double, storing it in the lower 64 of the temp result reg
        cdg.emit(ida_hexrays.m_f2f, r_mop, NO_MOP, t0_mop)

        # transfer the fully computed temp register to the real dest reg 
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, t0_result, 0, d_reg, 0)
        cdg.mba.free_kreg(t0_result, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vcvtsd2ss(self, cdg, insn):
        """
        VCVTSD2SS xmm1,xmm2,xmm3/m64
        """
        regs = self.xmm1_xmm2_xmm3_or_mem3()
        if regs is None:
            return ida_hexrays.MERR_INSN
        (d_reg, l_reg, r_reg) = regs

        r_mop = ida_hexrays.mop_t(r_reg, DOUBLE_SIZE)

        # op2 -- xmm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        # create a temp register to compute the final result into
        t0_result = cdg.mba.alloc_kreg(XMM_SIZE)
        t0_mop = ida_hexrays.mop_t(t0_result, FLOAT_SIZE)

        # copy xmm2 into the temp result reg, as we need its upper quadword
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, l_reg, 0, t0_result, 0)

        # convert float (op3) to a double, storing it in the lower 64 of the temp result reg
        cdg.emit(ida_hexrays.m_f2f, r_mop, NO_MOP, t0_mop)

        # transfer the fully computed temp register to the real dest reg
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, t0_result, 0, d_reg, 0)
        cdg.mba.free_kreg(t0_result, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    #-------------------------------------------------------------------------
    # Mov Instructions
    #-------------------------------------------------------------------------

    def vmovss(self, cdg, insn):
        """
        VMOVSS xmm1, xmm2, xmm3	
        VMOVSS xmm1, m32
        VMOVSS xmm1, xmm2, xmm3	
        VMOVSS m32, xmm1
        """
        return self.vmovs_(cdg, insn, FLOAT_SIZE)

    def vmovsd(self, cdg, insn):
        """
        VMOVSD xmm1, xmm2, xmm3
        VMOVSD xmm1, m64
        VMOVSD xmm1, xmm2, xmm3
        VMOVSD m64, xmm1
        """
        return self.vmovs_(cdg, insn, DOUBLE_SIZE)

    def vmovs_(self, cdg, insn, data_size):
        """
        Templated handler for scalar float/double mov instructions.
        """

        # op form: X, Y -- (2 operands)
        if insn.Op3.type == ida_ua.o_void:

            # op form: xmm1, m32/m64
            if is_xmm_reg(insn.Op1) and is_mem_op(insn.Op2):
                (d_reg, l_reg) = self.xmm1_xmm2_or_mem2()
                self.emit_clear_ymm(d_reg)
                self.emit_fp_instr_l_d(ida_hexrays.m_mov, ida_hexrays.mop_t(l_reg, data_size), ida_hexrays.mop_t(d_reg, data_size))
                # clear_upper(cdg, d_reg, data_size)

            # op form: m32/m64, xmm1
            elif is_mem_op(insn.Op1) and is_xmm_reg(insn.Op2):
                l_reg = self.xmmreg(insn.Op2)
                l_mop = ida_hexrays.mop_t(l_reg, data_size)
                # store xmm1[:data_size] into memory at [m32/m64] (op1)
                insn = cdg.store_operand(0, l_mop)
                insn.set_fpinsn()
            else:
                return self.decode_error('unknown format')
        # op form: xmm1, xmm2, xmm3 -- (3 operands)
        else:
            regs = (self.xmmreg(insn.Op1), self.xmmreg(insn.Op2), self.xmmreg(insn.Op3))
            if not all(regs):
                return self.decode_error("expected xmm, xmm, xmm form")

            (d_reg, l_reg, r_reg) = regs

            self.emit_clear_ymm(d_reg)
            self.emit_copy_bits_xmm_wide(d_reg, l_reg)
            self.emit_fp_instr_l_d(ida_hexrays.m_mov, ida_hexrays.mop_t(r_reg, data_size), ida_hexrays.mop_t(d_reg, data_size))

        return ida_hexrays.MERR_OK

        # failsafe
        assert "Unreachable..."
        return ida_hexrays.MERR_INSN 

    def vmovd(self, cdg, insn):
        """
        VMOVD xmm1, r32/m32
        VMOVD r32/m32, xmm1
        """
        return self._vmov(cdg, insn, DWORD_SIZE)
    
    def vmovq(self, cdg, insn):
        """
        VMOVQ xmm1, r64/m64
        VMOVQ r64/m64, xmm1
        """
        return self._vmov(cdg, insn, QWORD_SIZE)

    def _vmov(self, cdg, insn, data_size):
        """
        Templated handler for dword/qword mov instructions.
        """

        # op form: xmm1, rXX/mXX
        if is_xmm_reg(insn.Op1):

            # op2 -- m32/m64
            if is_mem_op(insn.Op2):
                l_reg = cdg.load_operand(1)

            # op2 -- r32/r64
            else:
                l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

            # wrap the source micro-reg as a micro-operand of the specified size
            l_mop = ida_hexrays.mop_t(l_reg, data_size)

            # op1 -- xmm1
            d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)
            d_mop = ida_hexrays.mop_t(d_reg, XMM_SIZE)

            # emit the microcode for this insn
            cdg.emit(ida_hexrays.m_xdu, l_mop, NO_MOP, d_mop)

            # clear upper 128 bits of ymm1
            clear_upper(cdg, d_reg)

            return ida_hexrays.MERR_OK

        # op form: rXX/mXX, xmm1
        else:
            assert is_xmm_reg(insn.Op2)

            # op2 -- xmm1
            l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)
            l_mop = ida_hexrays.mop_t(l_reg, data_size)

            # op1 -- m32/m64
            if is_mem_op(insn.Op1):
                cdg.store_operand(0, l_mop)

            # op1 -- r32/r64
            else:
                d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)
                d_mop = ida_hexrays.mop_t(d_reg, data_size)
                cdg.emit(ida_hexrays.m_mov, l_mop, NO_MOP, d_mop)

                #
                # TODO: the intel manual doesn't make it entierly clear here
                # if the upper bits of a r32 operation need to be cleared ?
                # 

            return ida_hexrays.MERR_OK
        
        # failsafe
        assert "Unreachable..."
        return ida_hexrays.MERR_INSN 

    def v_mov_ps_dq(self, cdg, insn):
        """
        VMOVAPS xmm1, xmm2/m128
        VMOVAPS ymm1, ymm2/m256
        VMOVAPS xmm2/m128, xmm1
        VMOVAPS ymm2/m256, ymm1

        VMOVUPS xmm1, xmm2/m128
        VMOVUPS ymm1, ymm2/m256
        VMOVUPS xmm2/m128, xmm1
        VMOVUPS ymm2/m256, ymm1

        VMOVDQA xmm1, xmm2/m128
        VMOVDQA xmm2/m128, xmm1
        VMOVDQA ymm1, ymm2/m256
        VMOVDQA ymm2/m256, ymm1

        VMOVDQU xmm1, xmm2/m128
        VMOVDQU xmm2/m128, xmm1
        VMOVDQU ymm1, ymm2/m256
        VMOVDQU ymm2/m256, ymm1

        VMOVAPD xmm1, xmm2/m128
        VMOVAPD xmm2/m128, xmm1
        VMOVAPD ymm1, ymm2/m256
        VMOVAPD ymm2/m256, ymm1
        """

        # op form: reg, [mem]
        if is_avx_reg(insn.Op1):
            op_size = XMM_SIZE if is_xmm_reg(insn.Op1) else YMM_SIZE

            # op2 -- m128/m256
            if is_mem_op(insn.Op2):
                l_reg = cdg.load_operand(1)

            # op2 -- xmm1/ymm1
            else:
                assert is_avx_reg(insn.Op2)
                l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

            # wrap the source micro-reg as a micro-operand
            l_mop = ida_hexrays.mop_t(l_reg, op_size)

            # op1 -- xmmX/ymmX
            d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)
            d_mop = ida_hexrays.mop_t(d_reg, op_size)

            # clear upper 128 bits of ymm1
            if op_size == XMM_SIZE:
                # clear_upper(cdg, d_reg)
                self.emit_clear_ymm(d_reg)

            # emit the microcode for this insn
            cdg.emit(ida_hexrays.m_mov, l_mop, NO_MOP, d_mop)

            return ida_hexrays.MERR_OK

        # op form: [mem], reg
        else:
            assert is_mem_op(insn.Op1) and is_avx_reg(insn.Op2)
            op_size = XMM_SIZE if is_xmm_reg(insn.Op2) else YMM_SIZE

            # op1 -- xmm1/ymm1
            l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)
            l_mop = ida_hexrays.mop_t(l_reg, op_size)

            # [m128/m256] = xmm1/ymm1
            cdg.store_operand(0, l_mop)
            return ida_hexrays.MERR_OK

        # failsafe
        assert "Unreachable..."
        return ida_hexrays.MERR_INSN 

    #-------------------------------------------------------------------------
    # Bitwise Instructions
    #-------------------------------------------------------------------------

    def v_bitwise_ps(self, cdg, insn):
        """
        VORPS xmm1, xmm2, xmm3/m128
        VORPS ymm1, ymm2, ymm3/m256

        VXORPS xmm1, xmm2, xmm3/m128
        VXORPS ymm1, ymm2, ymm3/m256

        VANDPS xmm1, xmm2, xmm3/m128
        VANDPS ymm1, ymm2, ymm3/m256

        VXORPD xmm1, xmm2, xmm3/m128
        VXORPD ymm1, ymm2, ymm3/m256
        """
        assert is_avx_reg(insn.Op1) and is_avx_reg(insn.Op2)
        op_size = XMM_SIZE if is_xmm_reg(insn.Op1) else YMM_SIZE

        # op3 -- m128/m256
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- xmm3/ymm3
        else:
            assert is_avx_reg(insn.Op3)
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)

        itype2mcode = \
        {
            ida_allins.NN_vorps: ida_hexrays.m_or,
            ida_allins.NN_vandps: ida_hexrays.m_and,
            ida_allins.NN_vandpd: ida_hexrays.m_and,
            ida_allins.NN_vxorps: ida_hexrays.m_xor,
            ida_allins.NN_vxorpd: ida_hexrays.m_xor,
        }

        # get the hexrays microcode op to use for this instruction
        mcode_op = itype2mcode[insn.itype]

        # wrap the source micro-reg as a micro-operand
        r_mop = ida_hexrays.mop_t(r_reg, op_size)

        # op2 -- xmm2/ymm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)
        l_mop = ida_hexrays.mop_t(l_reg, op_size)

        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)

        # emit the microcode for this insn
        cdg.emit(mcode_op, l_mop, r_mop, d_mop)

        # clear upper 128 bits of ymm1
        if op_size == XMM_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    #-------------------------------------------------------------------------
    # Arithmetic Instructions
    #-------------------------------------------------------------------------

    def v_math_ss(self, cdg, insn):
        """
        VADDSS    xmm1, xmm2, xmm3/m32
        VSUBSS    xmm1, xmm2, xmm3/m32
        VMULSS    xmm1, xmm2, xmm3/m32
        VDIVSS    xmm1, xmm2, xmm3/m32
        """
        return self._v_math_ss_sd(cdg, insn, FLOAT_SIZE)

    def v_math_sd(self, cdg, insn):
        """
        VADDSD    xmm1, xmm2, xmm3/m64
        VSUBSD    xmm1, xmm2, xmm3/m64
        VMULSD    xmm1, xmm2, xmm3/m64
        VDIVSD    xmm1, xmm2, xmm3/m64
        """
        return self._v_math_ss_sd(cdg, insn, DOUBLE_SIZE)

    def _v_math_ss_sd(self, cdg, insn, op_size):
        """
        Templated handler for scalar float/double math instructions.
        """
        assert is_avx_reg(insn.Op1) and is_avx_reg(insn.Op2)

        # op3 -- m32/m64
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- xmm3
        else:
            assert is_xmm_reg(insn.Op3)
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)

        # op2 -- xmm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        itype2mcode = \
        {
            ida_allins.NN_vaddss: ida_hexrays.m_fadd,
            ida_allins.NN_vaddsd: ida_hexrays.m_fadd,

            ida_allins.NN_vsubss: ida_hexrays.m_fsub,
            ida_allins.NN_vsubsd: ida_hexrays.m_fsub,

            ida_allins.NN_vmulss: ida_hexrays.m_fmul,
            ida_allins.NN_vmulsd: ida_hexrays.m_fmul,

            ida_allins.NN_vdivss: ida_hexrays.m_fdiv,
            ida_allins.NN_vdivsd: ida_hexrays.m_fdiv,
        }

        # get the hexrays microcode op to use for this instruction
        mcode_op = itype2mcode[insn.itype]

        # emit the microcode for this insn
        self.emit_clear_ymm(d_reg)
        l_mop = ida_hexrays.mop_t(l_reg, op_size)
        r_mop = ida_hexrays.mop_t(r_reg, op_size)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)
        self.emit_fp_instr_l_r_d(mcode_op, l_mop, r_mop, d_mop)

        return ida_hexrays.MERR_OK

    def _vfmaddxxxsd(self, cdg, insn):
        """
        VFMADD132SD xmm1, xmm2, xmm3/m64
        VFMADD213SD xmm1, xmm2, xmm3/m64
        VFMADD231SD xmm1, xmm2, xmm3/m64
        """

        regs = self.xmm1_xmm2_xmm3_or_mem3()
        if regs is None:
            return ida_hexrays.MERR_INSN
        (d_reg, l_reg, r_reg) = regs

        op_size = DOUBLE_SIZE
        # wrap the source micro-reg as a micro-operand
        r_mop = ida_hexrays.mop_t(r_reg, op_size)
        l_mop = ida_hexrays.mop_t(l_reg, op_size)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)

        order = []
        if insn.itype == ida_allins.NN_vfmadd132sd:
            order = [d_mop, r_mop, l_mop]
        elif insn.itype == ida_allins.NN_vfmadd213sd:
            order = [l_mop, d_mop, r_mop]
        elif insn.itype == ida_allins.NN_vfmadd231sd:
            order = [l_mop, r_mop, d_mop]
        else:
            return ida_hexrays.MERR_INSN

        t1 = cdg.mba.alloc_kreg(XMM_SIZE)
        t1_mop = ida_hexrays.mop_t(t1, op_size)

        # t1 = l * r
        cdg.emit(ida_hexrays.m_fmul, order[0], order[1], t1_mop)
        # t2 = t1 + d
        cdg.emit(ida_hexrays.m_fadd, t1_mop, order[2], d_mop)

        cdg.mba.free_kreg(t1, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vfmadd132sd(self, cdg, insn):
        return self._vfmaddxxxsd(cdg, insn)

    def vfmadd213sd(self, cdg, insn):
        return self._vfmaddxxxsd(cdg, insn)

    def vfmadd231sd(self, cdg, insn):
        return self._vfmaddxxxsd(cdg, insn)

    def _vfnmaddxxxsd(self, cdg, insn):
        """
        VFNMADD132SD xmm1, xmm2,xmm3/m64
        VFNMADD213SD xmm1, xmm2,xmm3/m64
        VFNMADD231SD xmm1, xmm2,xmm3/m64
        """

        regs = self.xmm1_xmm2_xmm3_or_mem3()
        if regs is None:
            return ida_hexrays.MERR_INSN
        (d_reg, l_reg, r_reg) = regs

        op_size = DOUBLE_SIZE
        # wrap the source micro-reg as a micro-operand
        r_mop = ida_hexrays.mop_t(r_reg, op_size)
        l_mop = ida_hexrays.mop_t(l_reg, op_size)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)

        order = []
        if insn.itype == ida_allins.NN_vfnmadd132sd:
            order = [d_mop, r_mop, l_mop]
        elif insn.itype == ida_allins.NN_vfnmadd213sd:
            order = [l_mop, d_mop, r_mop]
        elif insn.itype == ida_allins.NN_vfnmadd231sd:
            order = [l_mop, r_mop, d_mop]
        else:
            return ida_hexrays.MERR_INSN

        t1 = cdg.mba.alloc_kreg(XMM_SIZE)
        t1_mop = ida_hexrays.mop_t(t1, op_size)

        t2 = cdg.mba.alloc_kreg(XMM_SIZE)
        t2_mop = ida_hexrays.mop_t(t2, op_size)

        # t1 = l * r
        cdg.emit(ida_hexrays.m_fmul, order[0], order[1], t1_mop)
        # t2 = -t1
        cdg.emit(ida_hexrays.m_fneg, t1_mop, NO_MOP, t2_mop)
        # t3 = t2 + d
        cdg.emit(ida_hexrays.m_fadd, t2_mop, order[2], d_mop)

        cdg.mba.free_kreg(t1, XMM_SIZE)
        cdg.mba.free_kreg(t2, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vfnmadd132sd(self, cdg, insn):
        return self._vfnmaddxxxsd(cdg, insn)

    def vfnmadd213sd(self, cdg, insn):
        return self._vfnmaddxxxsd(cdg, insn)

    def vfnmadd231sd(self, cdg, insn):
        return self._vfnmaddxxxsd(cdg, insn)

    def _vfmsubxxxsd(self, cdg, insn):
        regs = self.xmm1_xmm2_xmm3_or_mem3()
        if regs is None:
            return ida_hexrays.MERR_INSN
        (d_reg, l_reg, r_reg) = regs

        op_size = DOUBLE_SIZE
        # wrap the source micro-reg as a micro-operand
        r_mop = ida_hexrays.mop_t(r_reg, op_size)
        l_mop = ida_hexrays.mop_t(l_reg, op_size)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)

        order = []
        if insn.itype == ida_allins.NN_vfmsub132sd:
            order = [d_mop, r_mop, l_mop]
        elif insn.itype == ida_allins.NN_vfmsub213sd:
            order = [l_mop, d_mop, r_mop]
        elif insn.itype == ida_allins.NN_vfmsub231sd:
            order = [l_mop, r_mop, d_mop]
        else:
            return ida_hexrays.MERR_INSN

        t1 = cdg.mba.alloc_kreg(XMM_SIZE)
        t1_mop = ida_hexrays.mop_t(t1, op_size)

        # t1 = l * r
        cdg.emit(ida_hexrays.m_fmul, order[0], order[1], t1_mop)
        # t2 = t1 - d
        cdg.emit(ida_hexrays.m_fsub, t1_mop, order[2], d_mop)

        cdg.mba.free_kreg(t1, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vfmsub132sd(self, cdg, insn):
        return self._vfmsubxxxsd(cdg, insn)

    def vfmsub213sd(self, cdg, insn):
        return self._vfmsubxxxsd(cdg, insn)

    def vfmsub231sd(self, cdg, insn):
        return self._vfmsubxxxsd(cdg, insn)

    def v_math_ps(self, cdg, insn):
        """
        VADDPS    xmm1, xmm2, xmm3/m128
        VADDPS    ymm1, ymm2, ymm3/m256

        VSUBPS    xmm1, xmm2, xmm3/m128
        VSUBPS    ymm1, ymm2, ymm3/m256

        VMULPS    xmm1, xmm2, xmm3/m128
        VMULPS    ymm1, ymm2, ymm3/m256

        VDIVPS    xmm1, xmm2, xmm3/m128
        VDIVPS    ymm1, ymm2, ymm3/m256
        """
        assert is_avx_reg(insn.Op1) and is_avx_reg(insn.Op2)
        op_size = XMM_SIZE if is_xmm_reg(insn.Op1) else YMM_SIZE

        # op3 -- m128/m256
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- xmm3/ymm3
        else:
            assert is_avx_reg(insn.Op3)
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)

        # op2 -- xmm2/ymm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)
        
        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)

        itype2name = \
        {
            ida_allins.NN_vaddps: "_mm%u_add_ps",
            ida_allins.NN_vsubps: "_mm%u_sub_ps", 
            ida_allins.NN_vmulps: "_mm%u_mul_ps",
            ida_allins.NN_vdivps: "_mm%u_div_ps",

            ida_allins.NN_vaddpd: "_mm%u_add_pd",
            ida_allins.NN_vsubpd: "_mm%u_sub_pd",
            ida_allins.NN_vmulpd: "_mm%u_mul_pd",
        }

        # create the intrinsic
        bit_size = bytes2bits(op_size)
        bit_str = "256" if op_size == YMM_SIZE else ""
        intrinsic_name = itype2name[insn.itype] % bytes2bits(op_size)

        avx_intrinsic = AVXIntrinsic(cdg, intrinsic_name)
        avx_intrinsic.add_argument_reg(l_reg, "__m%u" % bit_size)
        avx_intrinsic.add_argument_reg(r_reg, "__m%u" % bit_size)
        avx_intrinsic.set_return_reg(d_reg, "__m%u" % bit_size)
        avx_intrinsic.emit()
        
        # clear upper 128 bits of ymm1
        if op_size == XMM_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    #-------------------------------------------------------------------------
    # Misc Instructions
    #-------------------------------------------------------------------------

    def vsqrtss(self, cdg, insn):
        """
        VSQRTSS xmm1, xmm2, xmm3/m32
        """
        assert is_xmm_reg(insn.Op1) and is_xmm_reg(insn.Op2)

        # op3 -- xmm3
        if is_xmm_reg(insn.Op3):
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)

        # op3 -- m32
        else:
            assert is_mem_op(insn.Op3)
            r_reg = cdg.load_operand(2)

        # op2 - xmm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)
        
        # op1 - xmm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        # create a temp register to compute the final result into
        t0_result = cdg.mba.alloc_kreg(XMM_SIZE)

        # populate the dest reg
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, l_reg, 0, t0_result, 0)

        # mov.fpu call !fsqrt<fast:float xmm1_4.4>.4, t0_result_4.4
        avx_intrinsic = AVXIntrinsic(cdg, "fsqrt")
        avx_intrinsic.add_argument_reg_basic(r_reg, ida_typeinf.BT_FLOAT)
        avx_intrinsic.set_return_reg_basic(t0_result, ida_typeinf.BT_FLOAT)
        avx_intrinsic.emit()

        # store the fully computed result 
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, t0_result, 0, d_reg, 0)
        cdg.mba.free_kreg(t0_result, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vsqrtps(self, cdg, insn):
        """
        VSQRTPS xmm1, xmm2/m128
        VSQRTPS ymm1, ymm2/m256
        """
        op_size = XMM_SIZE if is_xmm_reg(insn.Op1) else YMM_SIZE

        # op2 -- m128/m256
        if is_mem_op(insn.Op2):
            r_reg = cdg.load_operand(1)

        # op2 -- xmm2/ymm2
        else:
            assert is_avx_reg(insn.Op2)
            r_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        # intrinsic: __m256 _mm256_cvtepi32_ps (__m256i a)
        bit_size = bytes2bits(op_size)
        bit_str = str(bit_size) if op_size == YMM_SIZE else ""
        intrinsic_name = "_mm%s_sqrt_ps" % bit_str

        avx_intrinsic = AVXIntrinsic(cdg, intrinsic_name)
        avx_intrinsic.add_argument_reg(r_reg, "__m%u" % bit_size)
        avx_intrinsic.set_return_reg(d_reg, "__m%u" % bit_size)
        avx_intrinsic.emit()

        # clear upper 128 bits of ymm1
        if op_size == XMM_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vshufps(self, cdg, insn):
        """
        VSHUFPS xmm1, xmm2, xmm3/m128, imm8
        VSHUFPS ymm1, ymm2, ymm3/m256, imm8
        """
        op_size = XMM_SIZE if is_xmm_reg(insn.Op1) else YMM_SIZE

        # op4 -- imm8
        assert insn.Op4.type == ida_ua.o_imm
        mask_value = insn.Op4.value
        
        # op3 -- m128/m256
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- xmm3/ymm3
        else:
            assert is_avx_reg(insn.Op3)
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)

        # op2 -- xmm2/ymm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)

        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)

        # 
        # intrinsics:
        #   __m128 _mm_shuffle_ps (__m128 a, __m128 b, unsigned int imm8)
        #   __m256 _mm256_shuffle_ps (__m256 a, __m256 b, const int imm8)
        #

        bit_size = bytes2bits(op_size)
        bit_str = str(bit_size) if op_size == YMM_SIZE else ""
        intrinsic_name = "_mm%s_shuffle_ps" % bit_str

        avx_intrinsic = AVXIntrinsic(cdg, intrinsic_name)
        avx_intrinsic.add_argument_reg(l_reg, "__m%u" % bit_size)
        avx_intrinsic.add_argument_reg(r_reg, "__m%u" % bit_size)
        avx_intrinsic.add_argument_imm(mask_value, ida_typeinf.BT_INT8)
        avx_intrinsic.set_return_reg(d_reg, "__m%u" % bit_size)
        avx_intrinsic.emit()

        # clear upper 128 bits of ymm1
        if op_size == XMM_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def minmaxsd(self, cdg, insn, funcName):
        """
        VMINSD xmm1, xmm2, xmm3/m64
        VMAXSD xmm1, xmm2, xmm3/m64
        """
        # op3 -- xmm3
        regs = self.xmm1_xmm2_xmm3_or_mem3()
        if regs is None:
            return ida_hexrays.MERR_INSN
        (d_reg, l_reg, r_reg) = regs

        t0_result = self.save_upper_bits(l_reg, XMM_SIZE)

        avx_intrinsic = AVXIntrinsic(cdg, funcName)
        avx_intrinsic.add_argument_reg_basic(l_reg, ida_typeinf.BTF_DOUBLE)
        avx_intrinsic.add_argument_reg_basic(r_reg, ida_typeinf.BTF_DOUBLE)
        avx_intrinsic.set_return_reg_basic(t0_result, ida_typeinf.BTF_DOUBLE)
        avx_intrinsic.emit()

        # store the fully computed result
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, t0_result, 0, d_reg, 0)
        cdg.mba.free_kreg(t0_result, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vmaxsd(self, cdg, insn):
        return self.minmaxsd(cdg, insn, "fmax")

    def vminsd(self, cdg, insn):
        return self.minmaxsd(cdg, insn, "fmin")

    def vpxor(self, cdg, insn):
        """
        VPXOR xmm1, xmm2, xmm3/m128 // AVX
        VPXOR ymm1, ymm2, ymm3/m256 // AVX2
        """
        if is_xmm_reg(insn.Op1) and is_xmm_reg(insn.Op2):
            op_size = XMM_SIZE
        elif is_ymm_reg(insn.Op1) and is_ymm_reg(insn.Op2):
            op_size = YMM_SIZE
        else:
            return ida_hexrays.MERR_INSN

        # op3 -- m128/m256
        if is_mem_op(insn.Op3):
            r_reg = cdg.load_operand(2)

        # op3 -- xmm3/ymm3
        elif is_xmm_reg(insn.Op3) and op_size == XMM_SIZE or is_ymm_reg(insn.Op3) and op_size == YMM_SIZE:
            r_reg = ida_hexrays.reg2mreg(insn.Op3.reg)
        else:
            return ida_hexrays.MERR_INSN

        # wrap the source micro-reg as a micro-operand
        r_mop = ida_hexrays.mop_t(r_reg, op_size)

        # op2 -- xmm2/ymm2
        l_reg = ida_hexrays.reg2mreg(insn.Op2.reg)
        l_mop = ida_hexrays.mop_t(l_reg, op_size)

        # op1 -- xmm1/ymm1
        d_reg = ida_hexrays.reg2mreg(insn.Op1.reg)
        d_mop = ida_hexrays.mop_t(d_reg, op_size)

        # emit the microcode for this insn
        cdg.emit(ida_hexrays.m_xor, l_mop, r_mop, d_mop)

        # clear upper 128 bits of ymm1
        if op_size == XMM_SIZE:
            clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

    def vroundsd(self, cdg, insn):
        """
        VROUNDSD xmm1, xmm2, xmm3/m64, imm8
        """
        # op3 -- xmm3
        regs = self.xmm1_xmm2_xmm3_or_mem3()
        if regs is None:
            return ida_hexrays.MERR_INSN
        (d_reg, l_reg, r_reg) = regs
        if insn.Op4.type != ida_ua.o_imm:
            return self.decode_error('op4')

        t0_result = self.save_upper_bits(l_reg, XMM_SIZE)

        avx_intrinsic = AVXIntrinsic(cdg, 'roundsd_avx' )
        avx_intrinsic.add_argument_reg_basic(l_reg, ida_typeinf.BTF_DOUBLE)
        avx_intrinsic.add_argument_reg_basic(r_reg, ida_typeinf.BTF_DOUBLE)
        avx_intrinsic.add_argument_imm(insn.Op4.value, ida_typeinf.BTF_BYTE)
        avx_intrinsic.set_return_reg_basic(t0_result, ida_typeinf.BTF_DOUBLE)
        avx_intrinsic.emit()

        # store the fully computed result
        cdg.emit(ida_hexrays.m_mov, XMM_SIZE, t0_result, 0, d_reg, 0)
        cdg.mba.free_kreg(t0_result, XMM_SIZE)

        # clear upper 128 bits of ymm1
        clear_upper(cdg, d_reg)

        return ida_hexrays.MERR_OK

#-----------------------------------------------------------------------------
# Plugin
#-----------------------------------------------------------------------------

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return MicroAVX()

class MicroAVX(ida_idaapi.plugin_t):
    """
    The IDA plugin stub for MicroAVX.
    """

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = "AVX support for the Hex-Rays x64 Decompiler"
    help = ""
    wanted_name = "MicroAVX"
    wanted_hotkey = ""
    loaded = False

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # only bother to load the plugin for relevant sessions
        if not is_amd64_idb():
            return ida_idaapi.PLUGIN_SKIP

        # ensure the x64 decompiler is loaded
        if ida_loader.load_plugin("hexx64") is None:
            print("failed to load Hexx64 Decompiler...")
            return ida_idaapi.PLUGIN_SKIP

        if not ida_hexrays.init_hexrays_plugin():
            print("failed to init Hexx64 Decompiler...")
            return ida_idaapi.PLUGIN_SKIP

        NO_MOP = ida_hexrays.mop_t()
        NO_MOP.zero()

        # initialize the AVX lifter 
        self.avx_lifter = AVXLifter()
        self.avx_lifter.install()
        sys.modules["__main__"].lifter = self.avx_lifter

        # mark the plugin as loaded
        self.loaded = True
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ida_kernwin.warning("%s cannot be run as a script in IDA." % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        if not self.loaded:
            return

        # hex-rays automatically cleans up decompiler hooks, so not much to do here...
        self.avx_lifter = None