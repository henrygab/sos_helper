"""Command modules.

Commands are grouped into modules inside this package.  Each module exposes a
``register_*()`` function that the application calls at startup to populate the
:class:`~serial_console.command_registry.CommandRegistry`.

TODO: normalize the register function signature so can automatically both
      import and register from a list of modules.

"""
