"""Envelope encryption for sensitive payloads at rest using AES-256-GCM and KMS key identifiers."""

import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backend.app.core.exceptions import PrivAIException
from backend.app.core.kms import BaseKMSClient, KMSException, get_kms_client


class EncryptionException(PrivAIException):
    """Raised when encryption or decryption operations fail."""

    def __init__(self, message: str, code: str = "ENCRYPTION_ERROR") -> None:
        super().__init__(message=message, code=code, status_code=500)


class PayloadEncryptor:
    """AES-256-GCM envelope encryptor with KMS key identifier binding and key rotation support."""

    def __init__(
        self,
        key: bytes | None = None,
        kms_client: BaseKMSClient | None = None,
    ) -> None:
        self.kms_client = kms_client or get_kms_client()
        self._manual_key = key
        if self._manual_key is not None:
            if len(self._manual_key) != 32:
                raise EncryptionException(
                    message=f"Encryption key must be exactly 32 bytes (got {len(self._manual_key)}).",
                    code="INVALID_ENCRYPTION_KEY",
                )

    def encrypt(
        self,
        plaintext: str,
        associated_data: str = "",
        key_id: str | None = None,
    ) -> str:
        """Encrypt plaintext string using AES-256-GCM and return encoded string with key identifier.

        Format: v2:{key_id}:{base64(nonce_12bytes + ciphertext_and_tag)}
        """
        try:
            if self._manual_key is not None:
                kid = key_id or "manual"
                enc_key = self._manual_key
            elif key_id is not None:
                kid = key_id
                enc_key = self.kms_client.get_encryption_key(key_id)
            else:
                kid, enc_key = self.kms_client.get_active_encryption_key()

            if len(enc_key) != 32:
                raise EncryptionException(
                    message=f"Encryption key must be exactly 32 bytes (got {len(enc_key)}).",
                    code="INVALID_ENCRYPTION_KEY",
                )

            aesgcm = AESGCM(enc_key)
            nonce = os.urandom(12)
            ad_bytes = associated_data.encode("utf-8") if associated_data else None
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), ad_bytes)
            b64_payload = base64.b64encode(nonce + ciphertext).decode("utf-8")
            return f"v2:{kid}:{b64_payload}"
        except KMSException as exc:
            raise EncryptionException(
                message=exc.message,
                code=exc.code,
            ) from exc
        except EncryptionException:
            raise
        except Exception as exc:
            raise EncryptionException(
                message="Failed to encrypt envelope payload.",
                code="ENCRYPTION_FAILED",
            ) from exc

    def decrypt(self, encoded_data: str, associated_data: str = "") -> str:
        """Decrypt encoded AES-256-GCM string with backward compatibility for legacy records.

        Supports:
        - v2 versioned format: 'v2:{key_id}:{base64_payload}'
        - legacy unversioned format: '{base64_payload}'
        """
        try:
            if encoded_data.startswith("v2:"):
                parts = encoded_data.split(":", 2)
                if len(parts) != 3:
                    raise EncryptionException("Malformed versioned payload format.")
                kid = parts[1]
                raw_b64 = parts[2]

                if self._manual_key is not None:
                    dec_key = self._manual_key
                else:
                    dec_key = self.kms_client.get_encryption_key(kid)
            else:
                # Legacy unversioned format: decode with active/manual key
                raw_b64 = encoded_data
                if self._manual_key is not None:
                    dec_key = self._manual_key
                else:
                    _, dec_key = self.kms_client.get_active_encryption_key()

            if len(dec_key) != 32:
                raise EncryptionException(
                    message=f"Encryption key must be exactly 32 bytes (got {len(dec_key)}).",
                    code="INVALID_ENCRYPTION_KEY",
                )

            raw = base64.b64decode(raw_b64)
            if len(raw) < 12:
                raise EncryptionException("Corrupt ciphertext payload: insufficient length.")
            nonce = raw[:12]
            ciphertext = raw[12:]
            ad_bytes = associated_data.encode("utf-8") if associated_data else None
            aesgcm = AESGCM(dec_key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, ad_bytes)
            return decrypted.decode("utf-8")
        except KMSException as exc:
            raise EncryptionException(
                message=exc.message,
                code=exc.code,
            ) from exc
        except EncryptionException:
            raise
        except Exception as exc:
            raise EncryptionException(
                message="Failed to decrypt envelope payload.",
                code="DECRYPTION_FAILED",
            ) from exc
