"""
AnswerChain Document Storage Abstraction (Phase 8).

Provides a secure, modular storage interface decoupling document persistence
from filesystem details. Allows transparent replacement with AWS S3, Google
Cloud Storage, or Encrypted Vault backends in future production deployments.
"""

import abc
import logging
import os
from typing import Optional

logger = logging.getLogger("document_storage")

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

DEFAULT_STORAGE_DIR = os.environ.get(
    "DOCUMENT_STORAGE_PATH",
    os.path.join(PROJECT_ROOT, "generated", "marksheets"),
)


class DocumentStorage(abc.ABC):
    """Abstract storage interface for official academic credentials and marksheets."""

    @abc.abstractmethod
    def save_document(
        self,
        name: str,
        content: bytes,
        content_type: Optional[str] = None,
    ) -> str:
        """Persist document bytes and return storage reference/path."""
        pass

    @abc.abstractmethod
    def get_document(self, name: str) -> Optional[bytes]:
        """Retrieve document bytes by identifier or filename."""
        pass

    @abc.abstractmethod
    def delete_document(self, name: str) -> bool:
        """Remove document from storage."""
        pass

    @abc.abstractmethod
    def exists(self, name: str) -> bool:
        """Check if document exists in storage."""
        pass

    @abc.abstractmethod
    def get_document_path(self, name: str) -> Optional[str]:
        """Return local file path if accessible locally (e.g. for Flask send_file)."""
        pass


class LocalDocumentStorage(DocumentStorage):
    """
    Secure local filesystem storage provider with path traversal protection
    and atomic file writes.
    """

    def __init__(self, base_dir: str = DEFAULT_STORAGE_DIR) -> None:
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_safe_path(self, name: str) -> str:
        """Sanitize filename and protect against path traversal."""
        raw_name = name.strip()
        if ".." in raw_name or raw_name.startswith("/") or raw_name.startswith("\\"):
            raise PermissionError(f"Path traversal attempt detected in document name: {name}")
        clean_name = os.path.basename(raw_name)
        if not clean_name or clean_name in (".", ".."):
            raise ValueError(f"Invalid document name: {name}")
        resolved = os.path.abspath(os.path.join(self.base_dir, clean_name))
        if not resolved.startswith(self.base_dir):
            raise PermissionError("Path traversal attempt detected.")
        return resolved

    def save_document(
        self,
        name: str,
        content: bytes,
        content_type: Optional[str] = None,
    ) -> str:
        if not content:
            raise ValueError("Cannot store empty document.")
        target_path = self._resolve_safe_path(name)
        temp_path = f"{target_path}.tmp"
        with open(temp_path, "wb") as f:
            f.write(content)
        os.replace(temp_path, target_path)
        logger.info("Saved document %s (%d bytes)", name, len(content))
        return target_path

    def get_document(self, name: str) -> Optional[bytes]:
        target_path = self._resolve_safe_path(name)
        try:
            if not os.path.isfile(target_path):
                return None
            with open(target_path, "rb") as f:
                return f.read()
        except (ValueError, PermissionError):
            raise
        except Exception as e:
            logger.error("Failed to read document %s: %s", name, e)
            return None

    def delete_document(self, name: str) -> bool:
        target_path = self._resolve_safe_path(name)
        try:
            if os.path.isfile(target_path):
                os.remove(target_path)
                return True
            return False
        except (ValueError, PermissionError):
            raise
        except Exception as e:
            logger.error("Failed to delete document %s: %s", name, e)
            return False

    def exists(self, name: str) -> bool:
        target_path = self._resolve_safe_path(name)
        return os.path.isfile(target_path)

    def get_document_path(self, name: str) -> Optional[str]:
        target_path = self._resolve_safe_path(name)
        if os.path.isfile(target_path):
            return target_path
        return None


# Default storage singleton
document_storage: DocumentStorage = LocalDocumentStorage()
