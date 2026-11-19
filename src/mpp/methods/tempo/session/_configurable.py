"""TIP-1166 configurable account voucher signatures (0x05 envelopes).

From T15, a TIP-1034 channel's voucher signer may be a TIP-1107 configurable
account. Its vouchers carry a configurable account signature,
"0x05 || rlp([account, [salt, version, threshold, [[owner, weight], ...]], [approval, ...]])",
where each approval is a primitive signature, in ascending owner order, over the
configurable account digest of the voucher digest.

The encodings mirror tempo-primitives "transaction::configurable_account" and
ox "tempo/AccountConfig". Owner approvals are verified for secp256k1 owners.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast

CONFIGURABLE_ACCOUNT_ADDRESS = "0xAACC000000000000000000000000000000000000"
"""The TIP-1107 configurable account precompile."""

SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT = 0x05
"""Type byte of a configurable account signature envelope."""

SIGNATURE_DOMAIN = b"tempo:configurable-account:signature"
ACCOUNT_DOMAIN = b"tempo:configurable-account:account"
CONFIG_DOMAIN = b"tempo:configurable-account:config"

MAX_OWNERS = 48
"""Most owners a configuration may list."""
MAX_SIGNATURES = 8
"""Most owner approvals one signature may carry."""

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class OwnerSigner(Protocol):
    """An owner key: a TempoAccount, or anything with an address and sign_hash()."""

    @property
    def address(self) -> str: ...

    def sign_hash(self, msg_hash: bytes) -> bytes: ...


def _keccak(data: bytes) -> bytes:
    from eth_hash.auto import keccak

    return keccak(data)


def _fixed_bytes(value: str, size: int, label: str) -> bytes:
    raw = b""
    if isinstance(value, str) and value.startswith("0x"):  # pyright: ignore[reportUnnecessaryIsInstance]
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError:
            raw = b""
    if len(raw) != size:
        raise ValueError(f"invalid {label}: {value!r}")
    return raw


def _address_bytes(value: str) -> bytes:
    return _fixed_bytes(value, 20, "address")


def _hex(raw: bytes) -> str:
    return "0x" + raw.hex()


def is_zero_hash(value: str | None) -> bool:
    """Whether a hex value is absent or zero."""
    return value is None or int(value, 16) == 0


@dataclass(frozen=True, slots=True)
class ConfigurableAccountOwner:
    """One weighted owner of a configurable account."""

    owner: str
    """Owner address."""
    weight: int
    """Nonzero owner weight (uint8)."""


@dataclass(frozen=True, slots=True)
class ConfigurableAccountConfig:
    """A configurable account configuration, as its signatures carry it."""

    salt: str
    """bytes32 salt that, with the initial owner set, derives the account address."""
    threshold: int
    """Minimum total owner weight that authorizes a signature (uint8)."""
    owners: tuple[ConfigurableAccountOwner, ...]
    """Owners in strictly ascending address order."""
    version: int = 0
    """Configuration version; zero is the initial configuration."""

    def validate(self, account: str | None = None) -> None:
        """Check the configuration as the chain does; raises ValueError.

        With account, a version-zero configuration must not list it as an owner.
        """
        _fixed_bytes(self.salt, 32, "salt")
        if not 0 <= self.version < 2**64:
            raise ValueError("config version out of range")
        if not self.owners:
            raise ValueError("config has no owners")
        if len(self.owners) > MAX_OWNERS:
            raise ValueError("config has too many owners")
        if not 0 < self.threshold < 256:
            raise ValueError("config threshold must be 1 to 255")
        addresses = [int.from_bytes(_address_bytes(o.owner), "big") for o in self.owners]
        if any(address == 0 for address in addresses):
            raise ValueError("config owner is the zero address")
        if self.version == 0 and account is not None:
            if int.from_bytes(_address_bytes(account), "big") in addresses:
                raise ValueError("configurable account cannot own itself")
        if any(not 0 < o.weight < 256 for o in self.owners):
            raise ValueError("config owner weight must be 1 to 255")
        if any(a >= b for a, b in zip(addresses, addresses[1:], strict=False)):
            raise ValueError("config owners must be distinct and ascending")
        if sum(o.weight for o in self.owners) > 255:
            raise ValueError("config total weight exceeds 255")
        heaviest = sorted((o.weight for o in self.owners), reverse=True)[:MAX_SIGNATURES]
        if self.threshold > sum(heaviest):
            raise ValueError("config threshold exceeds the weight 8 approvals can reach")

    def _owner_set(self) -> bytes:
        out = bytes([self.threshold, len(self.owners)])
        for owner in self.owners:
            out += _address_bytes(owner.owner) + bytes([owner.weight])
        return out

    def commitment(self) -> str:
        """The config commitment the chain stores for this configuration."""
        self.validate()
        salt = _fixed_bytes(self.salt, 32, "salt")
        preimage = CONFIG_DOMAIN + salt + self.version.to_bytes(8, "big") + self._owner_set()
        return _hex(_keccak(preimage))

    def derive_address(self) -> str:
        """The account address this configuration derives as an initial configuration."""
        self.validate()
        salt = _fixed_bytes(self.salt, 32, "salt")
        account = _hex(_keccak(ACCOUNT_DOMAIN + salt + self._owner_set())[-20:])
        if int(account, 16) == 0 or self.owner_weight(account) is not None:
            raise ValueError("config derives an invalid account address")
        return account

    def owner_weight(self, owner: str) -> int | None:
        """The configured weight of owner, else None."""
        target = owner.lower()
        for entry in self.owners:
            if entry.owner.lower() == target:
                return entry.weight
        return None

    def to_rlp(self) -> list[Any]:
        """The configuration's RLP list."""
        return [
            _fixed_bytes(self.salt, 32, "salt"),
            self.version,
            self.threshold,
            [[_address_bytes(o.owner), o.weight] for o in self.owners],
        ]


def configurable_account_digest(inner_digest: bytes, account: str, version: int) -> bytes:
    """The digest a configurable account's owners approve for inner_digest."""
    if len(inner_digest) != 32:
        raise ValueError("inner digest must be 32 bytes")
    return _keccak(
        SIGNATURE_DOMAIN + inner_digest + _address_bytes(account) + version.to_bytes(8, "big")
    )


def _rlp_uint(value: object, size: int) -> int:
    if not isinstance(value, bytes) or value[:1] == b"\x00" or len(value) > size:
        raise ValueError("invalid RLP integer")
    return int.from_bytes(value, "big")


def _rlp_list(value: object, size: int | None, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"malformed configurable account {label}")
    items = cast(list[object], value)
    if size is not None and len(items) != size:
        raise ValueError(f"malformed configurable account {label}")
    return items


def _rlp_bytes(value: object, size: int | None, label: str) -> bytes:
    if not isinstance(value, bytes) or (size is not None and len(value) != size):
        raise ValueError(f"malformed configurable account {label}")
    return value


def _recover_owner(digest: bytes, approval: bytes) -> str | None:
    """Recover a secp256k1 owner approval; rejects high-s and non-65-byte approvals."""
    from eth_account import Account

    if len(approval) != 65:
        return None
    v = approval[64]
    if v in (0, 1):
        v += 27
    s = int.from_bytes(approval[32:64], "big")
    if v not in (27, 28) or s == 0 or s > _SECP256K1_N // 2:
        return None
    try:
        owner: str = Account._recover_hash(  # pyright: ignore[reportPrivateUsage]
            digest, signature=approval[:64] + bytes([v])
        )
    except Exception:
        return None
    return owner


@dataclass(frozen=True, slots=True)
class ConfigurableAccountSignature:
    """A decoded 0x05 configurable account signature."""

    account: str
    config: ConfigurableAccountConfig
    approvals: tuple[bytes, ...]

    def encode(self) -> bytes:
        """The type-prefixed envelope bytes."""
        from mpp.methods.tempo import _rlp as rlp

        body = [_address_bytes(self.account), self.config.to_rlp(), list(self.approvals)]
        return bytes([SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT]) + rlp.encode(body)

    @classmethod
    def decode(cls, signature: bytes) -> ConfigurableAccountSignature:
        """Decode and shape-check a 0x05 envelope; raises ValueError."""
        from mpp.methods.tempo import _rlp as rlp

        if len(signature) < 2 or signature[0] != SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT:
            raise ValueError("not a configurable account signature")
        body = signature[1:]
        try:
            decoded: Any = rlp.decode(body)
            canonical = rlp.encode(decoded) == body
        except Exception as error:
            raise ValueError("malformed configurable account signature") from error
        if not canonical:
            raise ValueError("non-canonical configurable account signature")
        items = _rlp_list(decoded, 3, "signature")
        account_raw = _rlp_bytes(items[0], 20, "address")
        config_raw = _rlp_list(items[1], 4, "config")
        salt = _rlp_bytes(config_raw[0], 32, "config salt")
        owners: list[ConfigurableAccountOwner] = []
        for entry in _rlp_list(config_raw[3], None, "owners"):
            pair = _rlp_list(entry, 2, "owner")
            owner = _rlp_bytes(pair[0], 20, "owner")
            owners.append(ConfigurableAccountOwner(_hex(owner), _rlp_uint(pair[1], 1)))
        approvals = [
            _rlp_bytes(approval, None, "approval")
            for approval in _rlp_list(items[2], None, "approvals")
        ]
        if not 0 < len(approvals) <= MAX_SIGNATURES:
            raise ValueError("configurable account signature needs 1 to 8 approvals")
        config = ConfigurableAccountConfig(
            salt=_hex(salt),
            version=_rlp_uint(config_raw[1], 8),
            threshold=_rlp_uint(config_raw[2], 1),
            owners=tuple(owners),
        )
        account = _hex(account_raw)
        if int(account, 16) == 0:
            raise ValueError("configurable account is the zero address")
        config.validate(account)
        return cls(account=account, config=config, approvals=tuple(approvals))

    def verify_approvals(self, inner_digest: bytes) -> bool:
        """Whether the owner approvals of inner_digest reach the threshold.

        Approvals must come from distinct owners in ascending address order, and
        every approval must be needed: dropping the lightest falls below the threshold.
        """
        digest = configurable_account_digest(inner_digest, self.account, self.config.version)
        threshold = self.config.threshold
        previous = -1
        total = 0
        lightest = 256
        for index, approval in enumerate(self.approvals):
            owner = _recover_owner(digest, approval)
            if owner is None:
                return False
            weight = self.config.owner_weight(owner)
            if weight is None or int(owner, 16) <= previous:
                return False
            previous = int(owner, 16)
            total += weight
            lightest = min(lightest, weight)
            if total >= threshold and index + 1 != len(self.approvals):
                return False
        return threshold <= total < threshold + lightest


def is_configurable_signature(signature: str) -> bool:
    """Whether a 0x-hex signature is a 0x05 configurable account envelope."""
    return len(signature) > 4 and len(signature) != 132 and signature[:4].lower() == "0x05"


def verify_configurable_signature(
    signature: str,
    inner_digest: bytes,
    expected_signer: str,
    opening_commitment: str | None = None,
) -> bool:
    """Verify a 0x05 signature over inner_digest for expected_signer (TIP-1166).

    With a nonzero opening_commitment (the commitment the escrow cached at open) the
    signature's config must commit to it. With a zero or absent opening commitment the config
    must be version zero and derive the signer's address. Either way, the owner
    approvals must reach the config's threshold.
    """
    try:
        parsed = ConfigurableAccountSignature.decode(bytes.fromhex(signature.removeprefix("0x")))
        if parsed.account.lower() != expected_signer.lower():
            return False
        if is_zero_hash(opening_commitment):
            if parsed.config.version != 0:
                return False
            if parsed.config.derive_address() != parsed.account:
                return False
        else:
            assert opening_commitment is not None
            if int(parsed.config.commitment(), 16) != int(opening_commitment, 16):
                return False
    except ValueError:
        return False
    return parsed.verify_approvals(inner_digest)


class ConfigurableAccount:
    """A TIP-1107 configurable account that signs TIP-1034 vouchers with its owners' keys.

    Pass it as a session client's voucher_signer: channels name it as their
    authorized signer, open with its config commitment as the salt, and carry
    0x05 vouchers approved by owners whose weights reach the threshold.

    Args:
        address: The configurable account address.
        config: The account's current configuration (its version-zero config if it
            was never registered on chain).
        owners: Owner signers (such as TempoAccount) that may approve.
        root_key: The account's own secp256k1 key, for an EOA that adopted a configuration
            (TIP-1113). It signs vouchers of channels opened before the account had a config
            commitment, which the escrow still accepts from it.
        previous_configs: Configurations the account held before ``config``. A channel opened
            under one carries its commitment as salt, and only that configuration signs its
            vouchers until it closes.
    """

    def __init__(
        self,
        *,
        address: str,
        config: ConfigurableAccountConfig,
        owners: Sequence[OwnerSigner],
        root_key: OwnerSigner | None = None,
        previous_configs: Sequence[ConfigurableAccountConfig] = (),
    ) -> None:
        config.validate(address)
        for previous in previous_configs:
            previous.validate(address)
        self.previous_configs = tuple(previous_configs)
        self._address = _hex(_address_bytes(address))
        if root_key is not None and root_key.address.lower() != self._address:
            raise ValueError("root_key must be the configurable account's own key")
        self.root_key = root_key
        self.config = config
        self._owners = {owner.address.lower(): owner for owner in owners}
        self._approvers = self._select_approvers()
        self._owner_signers = tuple(owners)

    @classmethod
    def from_initial_config(
        cls, config: ConfigurableAccountConfig, owners: Sequence[OwnerSigner]
    ) -> ConfigurableAccount:
        """The account a version-zero config derives."""
        if config.version != 0:
            raise ValueError("an initial configurable account config has version 0")
        return cls(address=config.derive_address(), config=config, owners=owners)

    @property
    def address(self) -> str:
        """The configurable account address."""
        return self._address

    @property
    def commitment(self) -> str:
        """The commitment of the account's current configuration."""
        return self.config.commitment()

    def channel_signer(
        self, salt: str, *, root_key: OwnerSigner | None = None
    ) -> ConfigurableAccount | OwnerSigner:
        """The signer for vouchers of a channel with descriptor salt ``salt`` (TIP-1166).

        A channel this account opened while it had a config commitment carries that
        commitment as its salt and its opening commitment, so this account signs ``0x05``.
        A channel opened before then has a zero opening commitment: the escrow accepts
        ``0x05`` only from the version-zero config that derives this address, current or in
        ``previous_configs``, and otherwise a primitive signature from the account's own key:
        ``root_key`` here when this account was built without one.
        """
        if not is_zero_hash(salt) and int(salt, 16) == int(self.commitment, 16):
            return self
        if not is_zero_hash(salt):
            for previous in self.previous_configs:
                if int(salt, 16) == int(previous.commitment(), 16):
                    # The config the channel opened under, not the account's current one.
                    return ConfigurableAccount(
                        address=self._address,
                        config=previous,
                        owners=self._owner_signers,
                        root_key=self.root_key,
                    )
        for config in (self.config, *self.previous_configs):
            if config.version != 0:
                continue
            try:
                derived = config.derive_address() == self._address
            except ValueError:
                continue
            if not derived:
                continue
            if config is self.config:
                return self
            # Registered since: the version-zero config still signs pre-registration channels.
            return ConfigurableAccount(
                address=self._address,
                config=config,
                owners=self._owner_signers,
                root_key=self.root_key,
            )
        own_key = self.root_key if self.root_key is not None else root_key
        if own_key is not None and own_key.address.lower() == self._address:
            return own_key
        return self

    def _select_approvers(self) -> list[str]:
        available = [o for o in self.config.owners if o.owner.lower() in self._owners]
        chosen: list[ConfigurableAccountOwner] = []
        total = 0
        for owner in sorted(available, key=lambda o: o.weight, reverse=True):
            if total >= self.config.threshold or len(chosen) == MAX_SIGNATURES:
                break
            chosen.append(owner)
            total += owner.weight
        if total < self.config.threshold:
            raise ValueError("configurable account owners cannot reach the config threshold")
        # Every approval must be needed: drop ones the threshold can spare, lightest first.
        for owner in sorted(chosen, key=lambda o: o.weight):
            if total - owner.weight >= self.config.threshold:
                chosen.remove(owner)
                total -= owner.weight
        return sorted((o.owner.lower() for o in chosen), key=lambda a: int(a, 16))

    def sign_hash(self, msg_hash: bytes) -> bytes:
        """Sign a 32-byte digest; returns the 0x05 configurable account envelope."""
        digest = configurable_account_digest(msg_hash, self._address, self.config.version)
        approvals: list[bytes] = []
        for owner in self._approvers:
            signature = bytes(self._owners[owner].sign_hash(digest))
            if len(signature) != 65:
                raise ValueError("configurable account owners must sign with secp256k1")
            v = signature[64]
            approvals.append(signature[:64] + bytes([v + 27 if v in (0, 1) else v]))
        return ConfigurableAccountSignature(
            account=self._address, config=self.config, approvals=tuple(approvals)
        ).encode()


class SignerConfigChangedError(Exception):
    """A `topUp` reverted because the channel's voucher signer changed its configuration.

    From T15 (TIP-1166), a channel whose signer had a config commitment at open stays bound
    to it: once the signer's configuration changes (`SignerConfigChanged`), or a signer
    without one at open retires its root key (`RootKeyRetired`), the escrow refuses to add
    deposit. Vouchers already signed stay valid; close the channel and open a new one.
    """

    def __init__(self, *, signer: str, reason: str, channel_id: str | None = None) -> None:
        super().__init__(
            f"Channel voucher signer {signer} changed its configuration ({reason}); "
            "close the channel and open a new one."
        )
        self.signer = signer
        """The channel's voucher signer."""
        self.reason = reason
        """`SignerConfigChanged` or `RootKeyRetired`."""
        self.channel_id = channel_id
        """The channel whose top-up reverted, when known."""


class ConfigurableVouchersUnsupportedError(ValueError):
    """The server does not advertise `configurableVouchers`, so it would reject the
    configurable account vouchers of a channel this client would open."""

    def __init__(self, *, signer: str) -> None:
        super().__init__(
            f"Voucher signer {signer} is a configurable account, but the server does not "
            "accept configurable account vouchers (methodDetails.configurableVouchers)."
        )
        self.signer = signer
        """The configurable account voucher signer."""


def encode_get_config_commitment(account: str) -> str:
    """Calldata for the precompile's getConfigCommitment(address)."""
    selector = _keccak(b"getConfigCommitment(address)")[:4]
    return _hex(selector + b"\x00" * 12 + _address_bytes(account))
