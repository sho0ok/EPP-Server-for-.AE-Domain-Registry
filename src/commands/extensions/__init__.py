"""
EPP Extension Commands

Registry-specific extensions for EPP protocol:
- AE Extension: .ae TLD specific commands (ModifyRegistrant, TransferRegistrant)
- AR Extension: AusRegistry commands (Undelete, Unrenew, PolicyDelete, PolicyUndelete)
- AU Extension: .au TLD specific commands (ModifyRegistrant, TransferRegistrant)
"""

from src.commands.extensions.ae_extension import (
    AE_EXTENSION_HANDLERS,
    get_ae_extension_handler,
)

from src.commands.extensions.ar_extension import (
    AR_EXTENSION_HANDLERS,
    get_ar_extension_handler,
)

from src.commands.extensions.au_extension import (
    AU_EXTENSION_HANDLERS,
    get_au_extension_handler,
)

__all__ = [
    "AE_EXTENSION_HANDLERS",
    "get_ae_extension_handler",
    "AR_EXTENSION_HANDLERS",
    "get_ar_extension_handler",
    "AU_EXTENSION_HANDLERS",
    "get_au_extension_handler",
]
