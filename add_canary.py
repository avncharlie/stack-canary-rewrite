import gtirb_rewriting.driver
from gtirb_rewriting import * # pyright: ignore
from gtirb_capstone.instructions import GtirbInstructionDecoder
import gtirb
import gtirb_functions

import logging
import itertools
import capstone_gt

level = logging.DEBUG
logger = logging.getLogger('stack_canary_debug')
logging.basicConfig(
    level=level,
    format='%(name)s:%(levelname)s: %(message)s'
)

class AddCanaryPass(Pass):
    """
    Add stack canary at start and end of every function.
    """

    def find_prologue_and_epilogue(self,
                                   function: gtirb_functions.Function,
                                   decoder: GtirbInstructionDecoder):
        '''
        Find prologue or epilogue of function if it exists.
        Return (entry block, exit block, prologue, epilogue, stack space allocated for local vars)
        '''

        # get entry and exit block of function
        entry_blocks = function.get_entry_blocks()
        # bail if more than one entry to function
        if len(entry_blocks) != 1:
            print(entry_blocks)
            logger.warning(f'More than one function entry point unsupported (in function: {function.get_name()})')
            return
        entry_block = entry_blocks.pop()

        exit_blocks = function.get_exit_blocks()
        if len(exit_blocks) != 1:
            logger.warning(f'More than one function exit point unsupported (in function: {function.get_name()})')
            return
        exit_block = exit_blocks.pop()

        err_cannot_find_prologue = f"Cannot find prologue of function: {function.get_name()}"
        err_cannot_find_epilogue = f"Cannot find epilogue of function: {function.get_name()}"

        # confirm epilogue exists
        epilogue = list(decoder.get_instructions(exit_block))
        if len(epilogue) < 2:
            logger.debug(err_cannot_find_epilogue); return False
        epilogue = epilogue[len(epilogue)-2:]
        for i, expected in enumerate(['leave', 'ret']):
            if epilogue[i].insn_name() != expected:
                logger.debug(err_cannot_find_epilogue); return False 

        # quickcheck prologue exists
        stack_subtract = 0
        prologue = list(itertools.islice(decoder.get_instructions(entry_block), 3))
        if len(prologue) < 2:
            logger.debug(err_cannot_find_prologue); return False 
        for i, expected in enumerate(['push', 'mov', 'sub']):
            if prologue[i].insn_name() != expected:
                logger.debug(err_cannot_find_prologue); return False 

        # confirm prologue exists and retrieve stack space subtracted.

        # check that first instruction is: push rbp
        if len(prologue[0].operands) != 1:
            logger.debug(err_cannot_find_prologue); return False 
        i = prologue[0].operands[0]
        if not (i.type == capstone_gt.x86.X86_OP_REG and prologue[0].reg_name(i.reg) == 'rbp'):
            logger.debug(err_cannot_find_prologue); return False 

        # check second instruction is: mov rbp, rsp
        if len(prologue[1].operands) != 2:
            logger.debug(err_cannot_find_prologue); return False 
        for index, i in enumerate(prologue[1].operands):
            if i.type != capstone_gt.x86.X86_OP_REG:
                logger.debug(err_cannot_find_prologue); return False 
            if index == 0 and prologue[1].reg_name(i.reg) != 'rbp':
                logger.debug(err_cannot_find_prologue); return False 
            if index == 1 and prologue[1].reg_name(i.reg) != 'rsp':
                logger.debug(err_cannot_find_prologue); return False 

        # check third instruction is: sub rsp, N
        if len(prologue[2].operands) != 2:
            logger.debug(err_cannot_find_prologue); return False 
        for index, i in enumerate(prologue[2].operands):
            if index == 0 and not (i.type == capstone_gt.x86.X86_OP_REG and prologue[2].reg_name(i.reg) == 'rsp'):
                logger.debug(err_cannot_find_prologue); return False 
            if index == 1:
                if i.type != capstone_gt.x86.X86_OP_IMM:
                    logger.debug(err_cannot_find_prologue); return False 
                stack_subtract = i.imm

        return (entry_block, exit_block, prologue, epilogue, stack_subtract)

    def add_stack_canary_after_local_vars(self,
                                          function: gtirb_functions.Function,
                                          context: RewritingContext,
                                          decoder: GtirbInstructionDecoder):

        # get function prologue, epilogue and stack space allocated for local vars
        rval = self.find_prologue_and_epilogue(function, decoder)
        if not rval: return 
        entry_block, exit_block, prologue, epilogue, stack_subtract = rval

        canary_offset = stack_subtract + 16

        # add 0x10 bytes to stack (to store canary)
        # why 16 bytes instead of 8? stack must be 16 byte aligned or crashes happen
        sub_stack_ins_address = prologue[2].address - entry_block.address
        sub_stack_ins_size = prologue[2].size
        context.replace_at(
            entry_block,
            sub_stack_ins_address,
            sub_stack_ins_size,
            Patch.from_function(lambda _: f'sub ${hex(canary_offset)}, %rsp', Constraints())
        )

        # add instructions store canary in newly created space
        after_prologue_address = (prologue[2].address + prologue[2].size) - entry_block.address
        context.insert_at(
            entry_block,
            after_prologue_address,
            Patch.from_function(lambda _: f'''
                mov %fs:0x28,%rax
                mov %rax,-{hex(stack_subtract)}(%rbp)
                xor %eax,%eax
            ''', Constraints())
        )

        before_epilogue_address = epilogue[0].address - exit_block.address
        context.insert_at(
            exit_block,
            before_epilogue_address,
            Patch.from_function(lambda _: f'''
                mov -{hex(stack_subtract)}(%rbp),%rdx
                xor %fs:0x28,%rdx
                je .Lleave
                ud2         # should call stack_chk_fail
                .Lleave:
            ''', Constraints())
        )

    def add_stack_canary_before_rbp(self,
                                    function: gtirb_functions.Function,
                                    context: RewritingContext,
                                    decoder: GtirbInstructionDecoder):
        # get function prologue, epilogue and stack space allocated for local vars
        rval = self.find_prologue_and_epilogue(function, decoder)
        if not rval: return 
        entry_block, exit_block, prologue, epilogue, stack_subtract = rval 

        context.insert_at(
            entry_block,
            0,
            Patch.from_function(lambda _: f'''
                mov %fs:0x28,%rax       # load canary into rax
                xor %rbp,%rax           # xor canary with previous rbp
                pushq %rax              # push xorred canary on stack
                subq $8, %rsp           # add padding to keep 16 byte aligned
                xor %eax,%eax
            ''', Constraints())
        )

        after_leave_address = epilogue[1].address - exit_block.address
        context.insert_at(
            exit_block,
            after_leave_address,
            Patch.from_function(lambda _: f'''
                addq $8, %rsp           # remove padding bytes 
                popq %rdx               # get xorred canary into rdx
                xor %rbp,%rdx           # xor with previous rbp (restored from previous leave instruction)
                xor %fs:0x28,%rdx       # xor with canary. should be zero now
                je .Lleave
                ud2         # should call stack_chk_fail
                .Lleave:
            ''', Constraints())
        )

    def add_stack_canary(self,
                         function: gtirb_functions.Function,
                         context: RewritingContext,
                         decoder: GtirbInstructionDecoder):

        # get function prologue, epilogue and stack space allocated for local vars
        rval = self.find_prologue_and_epilogue(function, decoder)
        if not rval: return 
        entry_block, exit_block, prologue, epilogue, stack_subtract = rval

        # add 0x10 bytes to stack (to store canary)
        # why 16 bytes instead of 8? stack must be 16 byte aligned or crashes happen
        sub_stack_ins_address = prologue[2].address - entry_block.address
        sub_stack_ins_size = prologue[2].size
        context.replace_at(
            entry_block,
            sub_stack_ins_address,
            sub_stack_ins_size,
            Patch.from_function(lambda _: f'sub ${hex(stack_subtract+16)}, %rsp', Constraints())
        )

        # add instructions store canary in newly created space
        after_prologue_address = (prologue[2].address + prologue[2].size) - entry_block.address
        context.insert_at(
            entry_block,
            after_prologue_address,
            Patch.from_function(lambda _: f'''
                mov %fs:0x28,%rax
                mov %rax,-0x8(%rbp)                         # add canary after stored rbp
                xor %eax,%eax
                sub $16,%rbp                                # offset rbp by extra space we added to stack
            ''', Constraints())
        )

        before_epilogue_address = epilogue[0].address - exit_block.address
        context.insert_at(
            exit_block,
            before_epilogue_address,
            Patch.from_function(lambda _: f'''
                mov +0x8(%rbp),%rdx # load canary into rdx (+8 index as we moved rbp 0x1)
                xor %fs:0x28,%rdx   # xor rdx and canary
                je .Lleave          # if not zero...
                ud2                 # ... crash should call stack_chk_fail
                .Lleave:
                addq $16, %rbp      # move rbp back 0x1 to point to prev fp before leave; ret
            ''', Constraints())
        )

    def begin_module(self,
                     module: gtirb.module.Module,
                     functions: list[gtirb_functions.function.Function],
                     context: RewritingContext):

        print('----------------------------------------')

        decoder = GtirbInstructionDecoder(module.isa)
        for function in functions:
            # make sure we do not canary the _start function

            #if module.entry_point not in function.get_all_blocks() and function.get_name() == 'main':
            if module.entry_point not in function.get_all_blocks():
                self.add_stack_canary(function, context, decoder)

        print('----------------------------------------')

    @patch_constraints()
    def init_canary(self, context): # pyright: ignore
        return """
        movq $0xdeadbeef, %rax 
        pushq %rax
        pushq %rax
        nop
        """
    @patch_constraints()
    def check_canary(self, context): # pyright: ignore
        return """
        addq $16, %rsp
        """
    @patch_constraints()
    def deadbeef(self, context): # pyright: ignore
        return """
        nop
        nop
        nop
        """

if __name__ == "__main__":
    # Allow gtirb-rewriting to provide us a command line driver. See
    # docs/Drivers.md for details.
    gtirb_rewriting.driver.main(AddCanaryPass)
