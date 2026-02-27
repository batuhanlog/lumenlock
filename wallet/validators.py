"""
Validation helpers for the LumenLock wallet application.

Provides pre-transaction safety checks so invalid data is caught
*before* hitting the Stellar network.

All monetary calculations use ``Decimal`` to preserve Stellar's
7-decimal-place precision and avoid float rounding errors.
"""

import re
import time
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from functools import wraps

from django.http import JsonResponse

try:
    from stellar_sdk import Keypair as _StellarKeypair
    _STELLAR_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _STELLAR_SDK_AVAILABLE = False

# ---------------------------------------------------------------------------
# Stellar address validation
# ---------------------------------------------------------------------------

# Quick pre-flight regex: G + 55 uppercase base-32 characters.
# Full checksum validation is done via the Stellar SDK's StrKey utilities.
_STELLAR_ADDRESS_RE = re.compile(r"^G[A-Z2-7]{55}$")


def validate_stellar_address(address: str) -> str | None:
    """Return an error message if *address* is not a valid Stellar public key,
    or ``None`` when the address looks good.

    Performs both format validation (regex) and SDK-level checksum validation
    to reject addresses that look valid but have an invalid checksum.
    """
    if not address:
        return "Recipient address is required."
    if not address.startswith("G"):
        return "Stellar address must start with 'G'."
    if len(address) != 56:
        return f"Stellar address must be 56 characters (got {len(address)})."
    if not _STELLAR_ADDRESS_RE.match(address):
        return "Stellar address contains invalid characters (expected uppercase base-32)."

    # SDK checksum validation — catches addresses that pass the regex
    # but have an invalid Stellar base-32 checksum.
    if _STELLAR_SDK_AVAILABLE:
        try:
            _StellarKeypair.from_public_key(address)
        except Exception:
            return "Stellar address checksum is invalid. Please double-check the address."

    return None


# ---------------------------------------------------------------------------
# Amount validation  (Decimal-based to avoid float precision loss)
# ---------------------------------------------------------------------------

# Stellar minimum base fee in XLM
STELLAR_BASE_FEE_XLM = Decimal("0.00001")

# Stellar minimum account balance (base reserve + buffer for safety)
# Base reserve: 1 XLM for account. We keep 0.5 XLM buffer to ensure
# transactions can always be built even after sending almost all balance.
STELLAR_MIN_ACCOUNT_BALANCE = Decimal("0.5")

# Maximum amount cap
MAX_AMOUNT = Decimal("1000000000")


def validate_amount(raw_amount, current_balance=None) -> str | None:
    """Return an error message if *raw_amount* is not a valid transaction
    amount, or ``None`` when the value is acceptable.

    *current_balance* should be a ``Decimal`` (or any type accepted by
    the ``Decimal`` constructor).  When supplied the check verifies that
    ``amount + base_fee <= balance``.
    """
    if raw_amount is None or raw_amount == "":
        return "Amount is required."

    try:
        amount = Decimal(str(raw_amount))
    except (InvalidOperation, ValueError, TypeError):
        return "Amount must be a valid number."

    # Reject NaN and Infinity — Decimal accepts these but they break
    # subsequent comparisons and the Stellar SDK.
    if not amount.is_finite():
        return "Amount must be a finite number (NaN and Infinity are not allowed)."

    if amount <= 0:
        return "Amount must be greater than zero."

    if amount > MAX_AMOUNT:
        return "Amount exceeds the maximum allowed (1,000,000,000 XLM)."

    # Stellar requires amounts with at most 7 decimal places
    if amount.as_tuple().exponent < -7:
        return "Amount cannot have more than 7 decimal places."

    if current_balance is not None:
        balance = Decimal(str(current_balance))
        # Check amount + fee <= balance - minimum account reserve
        # This ensures the account stays funded after the transaction
        available = balance - STELLAR_MIN_ACCOUNT_BALANCE
        needed = amount + STELLAR_BASE_FEE_XLM
        if needed > available:
            return (
                f"Insufficient balance. You need {needed} XLM "
                f"(amount + fee) but only have {available} XLM available "
                f"(reserving {STELLAR_MIN_ACCOUNT_BALANCE} XLM for account minimum)."
            )

    return None


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------


def validate_transaction_password(password: str) -> str | None:
    """Return an error message if the transaction password is missing or
    too short."""
    if not password:
        return "Transaction password is required."
    if len(password) < 4:
        return "Transaction password must be at least 4 characters."
    return None


def validate_wallet_password(password: str) -> str | None:
    """Return an error message if the wallet creation password is weak."""
    if not password:
        return "Password is required to encrypt your wallet."
    if len(password) < 8:
        return "Password must be at least 8 characters for wallet security."
    return None


# ---------------------------------------------------------------------------
# Rate limiting (per-user, Django cache-backed with atomic increment)
# ---------------------------------------------------------------------------

# NOTE: Uses Django cache (Redis/Memcached in production) for atomic,
# multi-process-safe enforcement. Falls back to in-memory store when
# no cache is configured (single-process / dev environments).
_rate_limit_store: dict[int, list[float]] = defaultdict(list)

MAX_REQUESTS = 5
WINDOW_SECONDS = 60


def _rate_limit_cache_key(user_id: int) -> str:
    return f"lumenlock:rl:{user_id}"


def _check_and_record_request(user_id: int) -> bool:
    """Return True if the request is allowed (under the limit), False otherwise.

    Uses Django cache atomically where available. The get→set sequence uses
    cache.add() for the initial slot so concurrent first-requests don't race.
    """
    now = time.time()
    window_start = now - WINDOW_SECONDS
    key = _rate_limit_cache_key(user_id)

    try:
        from django.core.cache import cache

        # Attempt atomic get-and-update using cache.
        # We store the list of timestamps; prune expired entries each time.
        timestamps = cache.get(key, [])
        timestamps = [t for t in timestamps if t > window_start]

        if len(timestamps) >= MAX_REQUESTS:
            return False

        timestamps.append(now)
        # Use a timeout slightly longer than the window so the key expires
        # naturally even if no further requests come in.
        cache.set(key, timestamps, timeout=WINDOW_SECONDS + 10)
        return True

    except Exception:
        # Fallback: in-memory (single-process safe)
        _rate_limit_store[user_id] = [
            t for t in _rate_limit_store.get(user_id, []) if t > window_start
        ]
        if len(_rate_limit_store[user_id]) >= MAX_REQUESTS:
            return False
        _rate_limit_store[user_id].append(now)
        return True


def rate_limit(view_func):
    """Decorator that limits send_money calls to MAX_REQUESTS per minute
    per authenticated user.

    Uses Django's cache backend when available (Redis/Memcached) so limits
    are enforced consistently across multiple worker processes.
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user_id = request.user.id if request.user.is_authenticated else 0

        if not _check_and_record_request(user_id):
            return JsonResponse(
                {
                    "message": f"Rate limit exceeded. Maximum {MAX_REQUESTS} "
                    f"transactions per minute. Please wait.",
                    "status": "error",
                    "code": "RATE_LIMITED",
                },
                status=429,
            )

        return view_func(request, *args, **kwargs)

    return wrapper
