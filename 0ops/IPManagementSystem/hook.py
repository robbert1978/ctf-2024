import gdb


def create_hook(addr):
    """Creates a custom breakpoint that triggers at a specific RIP value."""
    class HookBreakpoint(gdb.Breakpoint):
        def __init__(self, addr):
            super().__init__(f"*{addr}", gdb.BP_BREAKPOINT)

        def stop(self):
            rax = gdb.parse_and_eval("$rax")
            print(f"Rax: ", hex(rax))
            # Add custom logic here if needed
            return False  # Continue execution automatically after hook

    # Instantiate the custom breakpoint
    HookBreakpoint(addr)
    print(f"HookBreakpoint set at ", hex(addr))

# Register the function in GDB


class HookCommand(gdb.Command):
    """Command to create a hook at a specific address."""

    def __init__(self):
        super().__init__("hook", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if not arg:
            print("Usage: hook <address>")
            return
        try:
            addr = gdb.parse_and_eval(arg)
            create_hook(addr)
        except gdb.error as e:
            print(f"Error: {e}")


HookCommand()
