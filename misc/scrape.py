import collections

import idc
import ida_name
import idautils
import ida_funcs
import ida_hexrays

#-----------------------------------------------------------------------------
# Scraping Code
#-----------------------------------------------------------------------------

class MinsnVisitor(ida_hexrays.minsn_visitor_t):
    """
    Hex-Rays Micro-instruction Visitor
    """
    found = set()

    def visit_minsn(self):

        # we only care about external (unsupported) instructions
        if self.curins.opcode != ida_hexrays.m_ext:
            return 0
        
        ins_text = idc.GetDisasm(self.curins.ea)
        ins_op = ins_text.split(" ")[0]

        print("- 0x%08X: UNSUPPORTED %s" % (self.curins.ea, ins_text))
        self.found.add(ins_op)
        return 0

def scrape_unsupported_instructions():
    """
    Scrape all 'external' (unsupported) decompiler instructions from this IDB.

    Returns a tuple of two maps:
        ext2func = { opcode: set([func_ea, func2_ea, ...]) }
        func2ext = { func_ea: set([opcode1, opcode2, opcode3]) }

    """
    miv = MinsnVisitor()
    ext2func = collections.defaultdict(set)
    func2ext = {}
    
    for address in idautils.Functions():
     
        #address = 0x1800017E0 
        print("0x%08X: DECOMPILING" % address)
        func = ida_funcs.get_func(address)
    
        func_mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        flags = ida_hexrays.DECOMP_NO_XREFS | ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_WARNINGS
        mba = ida_hexrays.gen_microcode(func_mbr, hf, None, flags, ida_hexrays.MMAT_GENERATED)
    
        if not mba:
            print(" - 0x%08x: FAILED %s" % (hf.errea, hf.str))
            continue
    
        miv.found = set()
        mba.for_all_insns(miv)
    
        # opcode --> [func_ea, func2_ea, ..]
        for ins_op in miv.found:
            ext2func[ins_op].add(address)
    
        # func_ea --> [ins_op, ins_op2, ..]
        func2ext[address] = miv.found

    print("\nDone scraping...\n")
    return (ext2func, func2ext)

def print_stats(ext2func):
    """
    Print stats about the scraped instructions.
    """
    print("-"*60)
    
    func_size_cache = {}
    all_funcs = set()
    
    print("\nFUNC USES -- UNSUPPORTED INSTR (%u types)\n" % len(ext2func))
    for key in sorted(ext2func, key=lambda key: len(ext2func[key]), reverse=True):
        function_addresses = ext2func[key]
        all_funcs |= function_addresses
    
        # print the unsupported instruction op, and how many funcs use it
        print(" - USES: %d - OP: %s" % (len(function_addresses), key))
    
        # compute the size of all the funcs that use this op..
        func_sizes = []
        for address in function_addresses:
    
            # try to grab the func size if we cached it already
            func_size = func_size_cache.get(address, None)
            if func_size:
                func_sizes.append((func_size, address))
                continue
    
            # compute the size oe the function
            func = ida_funcs.get_func(address)
            func_size = ida_funcs.calc_func_size(func)
            func_sizes.append((func_size, address))
    
            # cache the func size for future use
            func_size_cache[address] = func_size
    
        # print a few small functions that use this unsupported op..
        func_sizes.sort()
        for size, address in func_sizes[:5]:
            print(" -- SAMPLE FUNC 0x%08X (%u bytes)" % (address, size))

    print("\n" + "-"*60 + "\n")
    print("AFFLICTED FUNCTIONS (%u funcs)\n" % len(all_funcs))
    
    all_funcs = sorted(all_funcs)
    for ea in all_funcs:
        function_name = ida_name.get_short_name(ea)
        print("0x%08X: %s" % (ea, function_name))

#-----------------------------------------------------------------------------
# Main
#-----------------------------------------------------------------------------

print("Scraping instructions...")
ext2func, func2ext = scrape_unsupported_instructions()
print("Dumping results...")
print_stats(ext2func)
