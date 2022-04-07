import pkg_resources

from .abi import (  # NOQA
    decode_abi,
    decode_single,
    encode_abi,
    encode_single,
    is_encodable,
    is_encodable_type,
)

__version__ = 1#pkg_resources.get_distribution('eth-abi').version
