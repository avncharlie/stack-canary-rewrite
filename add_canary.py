import gtirb_rewriting.driver
from gtirb_rewriting import *


class AddCanaryPass(Pass):
    """
    Add stack canary at start and end of every function.
    """

    def begin_module(self, module, functions, context):
        context.register_insert(
            AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY),
            Patch.from_function(self.init_canary),
        )
        context.register_insert(
            AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT),
            Patch.from_function(self.check_canary),
        )

    @patch_constraints()
    def init_canary(self, context):
        return """
        movq $0xdeadbeef, %rax 
        pushq %rax
        pushq %rax
        nop
        """
    @patch_constraints()
    def check_canary(self, context):
        return """
        addq $16, %rsp
        """

if __name__ == "__main__":
    # Allow gtirb-rewriting to provide us a command line driver. See
    # docs/Drivers.md for details.
    gtirb_rewriting.driver.main(AddCanaryPass)
