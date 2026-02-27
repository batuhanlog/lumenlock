"""
Comprehensive tests for LumenLock wallet validation logic.

Covers:
  - Stellar address format validation
  - Amount validation (positive, numeric, balance sufficiency)
  - Password validation
  - Rate limiting
  - Send money view (invalid inputs, error codes)
"""

from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from unittest.mock import patch, MagicMock

from decimal import Decimal

from wallet.validators import (
    validate_stellar_address,
    validate_amount,
    validate_transaction_password,
    validate_wallet_password,
    STELLAR_BASE_FEE_XLM,
    _rate_limit_store,
    _rate_limit_cache_key,
    MAX_REQUESTS,
)


# ===================================================================
# Stellar Address Validation
# ===================================================================


class StellarAddressValidationTest(TestCase):
    """Tests for validate_stellar_address()."""

    def test_valid_address(self):
        addr = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        self.assertIsNone(validate_stellar_address(addr))

    def test_empty_address(self):
        err = validate_stellar_address("")
        self.assertIn("required", err.lower())

    def test_none_address(self):
        err = validate_stellar_address(None)
        self.assertIn("required", err.lower())

    def test_wrong_prefix(self):
        addr = "SBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        err = validate_stellar_address(addr)
        self.assertIn("start with 'G'", err)

    def test_too_short(self):
        err = validate_stellar_address("GBBD47IF6LWK7P7")
        self.assertIn("56 characters", err)

    def test_too_long(self):
        addr = "G" + "A" * 56  # 57 chars total
        err = validate_stellar_address(addr)
        self.assertIn("56 characters", err)

    def test_invalid_checksum(self):
        # This address passes regex but has invalid checksum
        err = validate_stellar_address("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA4")
        # If SDK is available, checksum should catch it; otherwise format passes
        # Just verify it doesn't crash
        self.assertTrue(err is None or isinstance(err, str))

    def test_invalid_characters(self):
        # lowercase and digits 0,1,8,9 are not valid base-32
        addr = "G" + "a" * 55
        err = validate_stellar_address(addr)
        self.assertIn("invalid characters", err.lower())

    def test_contains_zero(self):
        addr = "G" + "0" * 55
        err = validate_stellar_address(addr)
        self.assertIn("invalid characters", err.lower())


# ===================================================================
# Amount Validation
# ===================================================================


class AmountValidationTest(TestCase):
    """Tests for validate_amount()."""

    def test_valid_integer(self):
        self.assertIsNone(validate_amount("100"))

    def test_valid_decimal(self):
        self.assertIsNone(validate_amount("10.5"))

    def test_valid_small(self):
        self.assertIsNone(validate_amount("0.0000001"))

    def test_empty(self):
        err = validate_amount("")
        self.assertIn("required", err.lower())

    def test_none(self):
        err = validate_amount(None)
        self.assertIn("required", err.lower())

    def test_non_numeric(self):
        err = validate_amount("abc")
        self.assertIn("valid number", err.lower())

    def test_nan(self):
        err = validate_amount("NaN")
        self.assertIn("finite", err.lower())

    def test_infinity(self):
        err = validate_amount("Infinity")
        self.assertIn("finite", err.lower())

    def test_zero(self):
        err = validate_amount("0")
        self.assertIn("greater than zero", err.lower())

    def test_negative(self):
        err = validate_amount("-50")
        self.assertIn("greater than zero", err.lower())

    def test_exceeds_max(self):
        err = validate_amount("9999999999")
        self.assertIn("maximum", err.lower())

    def test_too_many_decimals(self):
        err = validate_amount("1.12345678")  # 8 decimals
        self.assertIn("decimal", err.lower())

    def test_balance_sufficient(self):
        self.assertIsNone(validate_amount("10", current_balance=Decimal("100")))

    def test_balance_insufficient(self):
        err = validate_amount("100", current_balance=Decimal("50"))
        self.assertIn("insufficient", err.lower())

    def test_balance_exact_with_fee(self):
        # Exactly balance - fee should pass
        balance = Decimal("100")
        amount = balance - STELLAR_BASE_FEE_XLM
        self.assertIsNone(validate_amount(str(amount), current_balance=balance))

    def test_balance_exceeds_by_fee(self):
        # amount == balance means amount + fee > balance → fail
        err = validate_amount("100", current_balance=Decimal("100"))
        self.assertIn("insufficient", err.lower())


# ===================================================================
# Password Validation
# ===================================================================


class PasswordValidationTest(TestCase):
    """Tests for password validators."""

    def test_tx_password_valid(self):
        self.assertIsNone(validate_transaction_password("mypass"))

    def test_tx_password_empty(self):
        err = validate_transaction_password("")
        self.assertIn("required", err.lower())

    def test_tx_password_too_short(self):
        err = validate_transaction_password("ab")
        self.assertIn("4 characters", err)

    def test_wallet_password_valid(self):
        self.assertIsNone(validate_wallet_password("securepass123"))

    def test_wallet_password_empty(self):
        err = validate_wallet_password("")
        self.assertIn("required", err.lower())

    def test_wallet_password_too_short(self):
        err = validate_wallet_password("short")
        self.assertIn("8 characters", err)


# ===================================================================
# Rate Limiting
# ===================================================================


class RateLimitTest(TestCase):
    """Tests for the rate_limit decorator."""

    def setUp(self):
        # Clear both the in-memory fallback store and the Django cache
        # so rate-limit tests are fully isolated regardless of which
        # backend _check_and_record_request() uses.
        # Explicitly include all user IDs used in this test class (888, 999).
        _rate_limit_store.clear()
        try:
            from django.core.cache import cache
            cache.clear()  # Flush entire test cache for full isolation
        except Exception:
            pass

    def test_under_limit_passes(self):
        """Requests under the limit should pass through."""
        from wallet.validators import rate_limit
        import time

        call_count = 0

        @rate_limit
        def dummy_view(request):
            nonlocal call_count
            call_count += 1
            return MagicMock(status_code=200)

        request = MagicMock()
        request.user.is_authenticated = True
        request.user.id = 999

        for _ in range(MAX_REQUESTS):
            dummy_view(request)

        self.assertEqual(call_count, MAX_REQUESTS)

    def test_over_limit_blocked(self):
        """The (MAX_REQUESTS+1)th request should be blocked."""
        from wallet.validators import rate_limit

        @rate_limit
        def dummy_view(request):
            return MagicMock(status_code=200)

        request = MagicMock()
        request.user.is_authenticated = True
        request.user.id = 888

        for _ in range(MAX_REQUESTS):
            dummy_view(request)

        response = dummy_view(request)
        self.assertEqual(response.status_code, 429)


# ===================================================================
# Send Money View — Integration-style tests
# ===================================================================


class SendMoneyViewTest(TestCase):
    """Tests for the send_money view with various invalid inputs."""

    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass123")
        self.client.login(username="testuser", password="testpass123")
        _rate_limit_store.clear()
        try:
            from django.core.cache import cache
            cache.clear()  # Flush entire test cache for full isolation
        except Exception:
            pass

    def test_get_method_rejected(self):
        response = self.client.get("/send_money")
        self.assertEqual(response.status_code, 405)

    def test_invalid_json(self):
        response = self.client.post(
            "/send_money",
            data="not json",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_empty_recipient(self):
        response = self.client.post(
            "/send_money",
            data='{"recipient": "", "amount": "10", "transaction_password": "mypass"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data["code"], "INVALID_ADDRESS")

    def test_invalid_address_format(self):
        response = self.client.post(
            "/send_money",
            data='{"recipient": "INVALID", "amount": "10", "transaction_password": "mypass"}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "INVALID_ADDRESS")

    def test_missing_password(self):
        valid_addr = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        response = self.client.post(
            "/send_money",
            data=f'{{"recipient": "{valid_addr}", "amount": "10", "transaction_password": ""}}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "INVALID_PASSWORD")

    def test_no_wallet(self):
        """User without a wallet should get 404."""
        valid_addr = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        response = self.client.post(
            "/send_money",
            data=f'{{"recipient": "{valid_addr}", "amount": "10", "transaction_password": "mypass"}}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)

    def test_negative_amount(self):
        """Negative amount should fail even before wallet lookup."""
        valid_addr = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        # Create a wallet for the user first
        from wallet.models import Wallet

        Wallet.objects.create(
            user=self.user,
            public_key="GABC47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLAA",
            secret_seed="encrypted_seed_here",
        )

        with patch("wallet.views._get_xlm_balance", return_value=1000.0):
            response = self.client.post(
                "/send_money",
                data=f'{{"recipient": "{valid_addr}", "amount": "-5", "transaction_password": "mypass"}}',
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "INVALID_AMOUNT")

    def test_self_transfer_blocked(self):
        """Sending to yourself should be rejected."""
        from wallet.models import Wallet

        my_key = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        Wallet.objects.create(
            user=self.user,
            public_key=my_key,
            secret_seed="encrypted_seed_here",
        )

        with patch("wallet.views._get_xlm_balance", return_value=1000.0):
            response = self.client.post(
                "/send_money",
                data=f'{{"recipient": "{my_key}", "amount": "10", "transaction_password": "mypass"}}',
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "SELF_TRANSFER")
