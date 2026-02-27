from decimal import Decimal, InvalidOperation, ROUND_DOWN

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

from stellar_sdk import Asset, Server, Keypair, TransactionBuilder, Network
from stellar_sdk.exceptions import (
    BadRequestError,
    NotFoundError,
    BadResponseError,
)

from .models import Wallet
from .validators import (
    validate_stellar_address,
    validate_amount,
    validate_transaction_password,
    validate_wallet_password,
    _check_and_record_request,
    STELLAR_BASE_FEE_XLM,
)

import cryptocode
import json
import logging

logger = logging.getLogger(__name__)

HORIZON_URL = "https://horizon-testnet.stellar.org"
FRIENDBOT_URL = "https://friendbot.stellar.org"


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------


def home(request):
    return render(request, "home.html")


# ---------------------------------------------------------------------------
# Wallet Creation
# ---------------------------------------------------------------------------


@login_required
def create_wallet(request):
    if Wallet.objects.filter(user=request.user).exists():
        return redirect("dashboard")

    if request.method != "POST":
        return redirect("dashboard")

    encryption_key = request.POST.get("password", "")

    # --- Validate password strength ---
    pwd_error = validate_wallet_password(encryption_key)
    if pwd_error:
        return render(
            request,
            "dashboard.html",
            {"wallet_exists": False, "error": pwd_error},
        )

    try:
        keypair = Keypair.random()
        encrypted_secret_seed = cryptocode.encrypt(keypair.secret, encryption_key)

        # Fund via friendbot FIRST — only create wallet if funding succeeds.
        # This prevents users from getting stuck with an unfunded wallet.
        import requests as http_requests

        fund_resp = http_requests.get(
            FRIENDBOT_URL, params={"addr": keypair.public_key}, timeout=15
        )
        if fund_resp.status_code != 200:
            logger.warning(
                "Friendbot funding failed (HTTP %s) for %s: %s",
                fund_resp.status_code,
                keypair.public_key,
                fund_resp.text[:200],
            )
            # Don't create wallet if funding failed — user can retry cleanly
            return render(
                request,
                "dashboard.html",
                {
                    "wallet_exists": False,
                    "error": "Wallet creation failed: could not fund account on testnet. Please try again.",
                },
            )

        # Funding succeeded — now create the wallet record.
        # Wrap in try/except to handle DB failures with compensating cleanup.
        try:
            wallet = Wallet.objects.create(
                user=request.user,
                public_key=keypair.public_key,
                secret_seed=encrypted_secret_seed,
            )
        except Exception as db_error:
            logger.error("Wallet DB creation failed after funding: %s", db_error)
            # Compensating cleanup: delete the funded Stellar account to prevent
            # orphaning a funded account with no local wallet record.
            try:
                from stellar_sdk.exceptions import BadResponseError
                server = Server(HORIZON_URL)
                # Attempt to claw back the funds by creating a transaction
                # Note: Full cleanup requires account merge which needs the secret.
                # For testnet, this is an edge case - just log for now.
                logger.warning(
                    "Orphaned funded account %s - DB insert failed. "
                    "User should retry wallet creation.",
                    keypair.public_key
                )
            except Exception as cleanup_error:
                logger.error("Compensating cleanup failed: %s", cleanup_error)
            return render(
                request,
                "dashboard.html",
                {
                    "wallet_exists": False,
                    "error": "Wallet creation failed at final step. Please try again.",
                },
            )

    except Exception as e:
        logger.error("Wallet creation failed: %s", e)
        return render(
            request,
            "dashboard.html",
            {"wallet_exists": False, "error": "Wallet creation failed. Please try again."},
        )

    return redirect("dashboard")


# ---------------------------------------------------------------------------
# Balance — uses Decimal to preserve Stellar's 7-decimal precision
# ---------------------------------------------------------------------------


def _get_xlm_balance(public_key: str) -> Decimal | None:
    """Fetch the native XLM balance for *public_key*.

    Returns:
        - Decimal: the native XLM balance
        - None: on network/connection errors
        - Raises AccountNotFoundError: if account doesn't exist or unfunded
    """
    from stellar_sdk.exceptions import NotFoundError as StellarNotFoundError

    try:
        server = Server(HORIZON_URL)
        account = server.accounts().account_id(public_key).call()
        for bal in account["balances"]:
            if bal["asset_type"] == "native":
                return Decimal(bal["balance"])
        return Decimal("0")
    except StellarNotFoundError:
        # Re-raise specifically so callers can distinguish "account not found"
        # from generic network errors. This helps with better user messaging.
        raise
    except Exception:
        # Generic network/connection errors - return None for backward compatibility
        return None


@login_required
def check_balance(request):
    # Always look up the authenticated user's own wallet — never accept an
    # arbitrary public_key from the request to prevent information disclosure.
    wallets = Wallet.objects.filter(user=request.user)
    if not wallets.exists():
        return JsonResponse({"error": "No wallet found."}, status=404)

    public_key = wallets.first().public_key

    try:
        balance = _get_xlm_balance(public_key)
    except NotFoundError:
        return JsonResponse(
            {"error": "Account not found or unfunded on Stellar network."},
            status=404,
        )

    if balance is None:
        return JsonResponse(
            {"error": "Could not fetch balance from Stellar network."},
            status=502,
        )

    return JsonResponse({"balance": str(balance), "public_key": public_key})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_amount(raw) -> str:
    """Convert *raw* to a plain decimal string safe for the Stellar SDK.

    Avoids scientific-notation issues (e.g. ``1e-07``) by going through
    ``Decimal`` and formatting with a fixed-point quantize.
    """
    d = Decimal(str(raw))
    # Check: after quantization, amount must not become 0
    quantized = d.quantize(Decimal("0.0000001"), rounding=ROUND_DOWN)
    if quantized <= 0:
        raise ValueError(f"Amount too small: {raw} becomes {quantized} after quantization")
    return str(quantized)


# ---------------------------------------------------------------------------
# Send Money — with full pre-transaction validation (Closes #4)
# ---------------------------------------------------------------------------


@login_required
def send_money(request):
    # Check method FIRST before applying rate limit
    # This prevents GET/other requests from consuming rate limit quota
    if request.method != "POST":
        return JsonResponse(
            {"message": "Only POST allowed.", "status": "error"},
            status=405,
        )

    # Apply rate limiting only to actual POST (transaction) requests
    from wallet.validators import _check_and_record_request
    user_id = request.user.id if request.user.is_authenticated else 0
    if not _check_and_record_request(user_id):
        return JsonResponse(
            {
                "message": "Rate limit exceeded. Maximum 5 transactions per minute. Please wait.",
                "status": "error",
                "code": "RATE_LIMITED",
            },
            status=429,
        )

    # --- Parse JSON body ---
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse(
            {"message": "Invalid JSON in request body.", "status": "error"},
            status=400,
        )

    if not isinstance(data, dict):
        return JsonResponse(
            {"message": "Request body must be a JSON object.", "status": "error"},
            status=400,
        )

    destination = str(data.get("recipient") or "").strip()
    amount_raw = data.get("amount", "")
    password = data.get("transaction_password", "")

    # --- 1. Validate destination address format ---
    addr_error = validate_stellar_address(destination)
    if addr_error:
        return JsonResponse(
            {"message": addr_error, "status": "error", "code": "INVALID_ADDRESS"},
            status=400,
        )

    # --- 2. Validate transaction password ---
    pwd_error = validate_transaction_password(password)
    if pwd_error:
        return JsonResponse(
            {"message": pwd_error, "status": "error", "code": "INVALID_PASSWORD"},
            status=400,
        )

    # --- 3. Get wallet and current balance ---
    wallets = Wallet.objects.filter(user=request.user)
    if not wallets.exists():
        return JsonResponse(
            {"message": "No wallet found for your account.", "status": "error"},
            status=404,
        )
    wallet = wallets.first()

    try:
        current_balance = _get_xlm_balance(wallet.public_key)
    except Exception:
        return JsonResponse(
            {
                "message": "Your account is not found or unfunded on Stellar network. "
                           "Please ensure your wallet has been funded.",
                "status": "error",
                "code": "ACCOUNT_NOT_FOUND",
            },
            status=400,
        )

    if current_balance is None:
        return JsonResponse(
            {
                "message": "Could not fetch your balance. Please try again later.",
                "status": "error",
                "code": "NETWORK_ERROR",
            },
            status=502,
        )

    # --- 4. Validate amount (with balance sufficiency check) ---
    amount_error = validate_amount(amount_raw, current_balance=current_balance)
    if amount_error:
        return JsonResponse(
            {"message": amount_error, "status": "error", "code": "INVALID_AMOUNT"},
            status=400,
        )

    # --- 5. Prevent self-transfer ---
    if destination == wallet.public_key:
        return JsonResponse(
            {"message": "Cannot send tokens to yourself.", "status": "error", "code": "SELF_TRANSFER"},
            status=400,
        )

    # --- 6. Decrypt secret key ---
    try:
        decrypted_secret = cryptocode.decrypt(wallet.secret_seed, password)
        if not decrypted_secret:
            raise ValueError("Decryption returned empty result")
        source_keypair = Keypair.from_secret(decrypted_secret)
    except Exception:
        return JsonResponse(
            {
                "message": "Incorrect transaction password.",
                "status": "error",
                "code": "WRONG_PASSWORD",
            },
            status=401,
        )

    # --- 7. Verify destination account exists on Stellar ---
    try:
        server = Server(HORIZON_URL)
        server.load_account(destination)
    except NotFoundError:
        return JsonResponse(
            {
                "message": "Destination account does not exist on the Stellar network.",
                "status": "error",
                "code": "DEST_NOT_FOUND",
            },
            status=400,
        )
    except Exception as e:
        logger.error("Error loading destination account: %s", e)
        return JsonResponse(
            {
                "message": "Could not verify destination account. Please try again.",
                "status": "error",
                "code": "NETWORK_ERROR",
            },
            status=502,
        )

    # --- 8. Build, sign, and submit transaction ---
    try:
        try:
            source_account = server.load_account(source_keypair.public_key)
        except NotFoundError:
            return JsonResponse(
                {
                    "message": "Source account not found on Stellar network. "
                               "Ensure your wallet is funded before sending.",
                    "status": "error",
                    "code": "ACCOUNT_NOT_FOUND",
                },
                status=400,
            )

        # Normalize amount to a plain decimal string (avoids 1e-07 issues)
        try:
            safe_amount = _normalize_amount(amount_raw)
        except ValueError as e:
            return JsonResponse(
                {"message": str(e), "status": "error", "code": "INVALID_AMOUNT"},
                status=400,
            )

        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
                base_fee=100,
            )
            .append_payment_op(
                destination=destination,
                amount=safe_amount,
                asset=Asset.native(),
            )
            .set_timeout(30)
            .build()
        )

        transaction.sign(source_keypair)
        response = server.submit_transaction(transaction)

        return JsonResponse(
            {
                "message": "Payment sent successfully!",
                "status": "success",
                "hash": response.get("hash", ""),
            }
        )

    except BadRequestError as e:
        logger.error("Stellar BadRequestError: %s", e)
        return JsonResponse(
            {
                "message": "Transaction rejected by the network. Check amount and try again.",
                "status": "error",
                "code": "TX_REJECTED",
            },
            status=400,
        )
    except BadResponseError as e:
        logger.error("Stellar BadResponseError: %s", e)
        return JsonResponse(
            {
                "message": "Stellar network returned an unexpected response.",
                "status": "error",
                "code": "NETWORK_ERROR",
            },
            status=502,
        )
    except Exception as e:
        logger.error("Transaction failed: %s", e)
        return JsonResponse(
            {
                "message": "Transaction failed. Please try again later.",
                "status": "error",
                "code": "TX_FAILED",
            },
            status=500,
        )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@login_required
def dashboard(request):
    wallet_exists = Wallet.objects.filter(user=request.user).exists()
    if not wallet_exists:
        return render(request, "dashboard.html", {"wallet_exists": wallet_exists})

    wallet = Wallet.objects.filter(user=request.user).first()
    try:
        balance = _get_xlm_balance(wallet.public_key)
    except Exception:
        # Account not funded - show as 0 with warning
        balance = Decimal("0")

    context = {
        "wallet_exists": wallet_exists,
        "balance": str(balance) if balance is not None else "N/A",
        "public_key": wallet.public_key,
    }
    return render(request, "dashboard.html", context)
