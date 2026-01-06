# backend/app/security/totp.py
"""
TOTP (Time-based One-Time Password) implementation
RFC 6238 compliant - Compatible with Google Authenticator, Authy, Aegis

Key points:
- 6-digit codes
- 30-second time step
- HMAC-SHA1 (standard)
- Base32 secret encoding
"""
import pyotp
import qrcode
import io
import base64


def generate_totp_secret() -> str:
    """
    Generate a new random TOTP secret (Base32 encoded).
    Returns 32-character Base32 string.
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "Pallium") -> str:
    """
    Generate the otpauth:// URI for QR code encoding.

    Format: otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}

    This is what gets encoded in the QR code.
    Authenticator apps scan this to add the account.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_base64(secret: str, username: str, issuer: str = "Pallium") -> str:
    """
    Generate a QR code image as Base64-encoded PNG.

    The QR code encodes the otpauth:// URI.
    Frontend can display this directly using: <img src="data:image/png;base64,{result}">
    """
    uri = get_totp_uri(secret, username, issuer)

    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to Base64
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return base64.b64encode(buffer.read()).decode("utf-8")


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code.
    Returns True if valid, False otherwise.
    """
    if not secret or not code:
        return False

    code = code.strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return False

    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def get_current_totp(secret: str) -> str:
    """
    Get the current TOTP code for a secret.
    Useful for testing only - never expose this in production!
    """
    totp = pyotp.TOTP(secret)
    return totp.now()

