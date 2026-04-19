"""Hash extraction module.

This module provides functionality to extract various types of hashes from email content,
including MD5, SHA1, SHA256, and other cryptographic hashes commonly found in malware.
"""

import re
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class ExtractedHash:
    """Extracted hash with metadata."""

    hash_value: str
    hash_type: str
    length: int
    is_valid: bool


def extract_hashes(text: str) -> List[ExtractedHash]:
    """Extract all hash types from text content.

    Args:
        text: Text content to scan

    Returns:
        List of ExtractedHash objects

    Example:
        >>> text = "File hash: 44d88612fceea9c2e22c9ebb2a3e3f0e"
        >>> hashes = extract_hashes(text)
        >>> print(hashes[0].hash_type)
        md5
    """
    hashes = []
    seen_hashes = set()

    hash_patterns = {
        'md5': re.compile(r'\b[0-9a-fA-F]{32}\b'),
        'sha1': re.compile(r'\b[0-9a-fA-F]{40}\b'),
        'sha256': re.compile(r'\b[0-9a-fA-F]{64}\b'),
        'sha512': re.compile(r'\b[0-9a-fA-F]{128}\b'),
    }

    for hash_type, pattern in hash_patterns.items():
        for match in pattern.finditer(text):
            hash_value = match.group(0).lower()

            if hash_value in seen_hashes:
                continue
            seen_hashes.add(hash_value)

            is_valid = validate_hash(hash_value, hash_type)

            if is_valid:
                hashes.append(ExtractedHash(
                    hash_value=hash_value,
                    hash_type=hash_type,
                    length=len(hash_value),
                    is_valid=True
                ))

    hashes.sort(key=lambda x: x.length)
    return hashes


def extract_md5(text: str) -> List[ExtractedHash]:
    """Extract MD5 hashes from text.

    Args:
        text: Text content to scan

    Returns:
        List of MD5 hashes
    """
    hashes = []
    pattern = re.compile(r'\b[0-9a-fA-F]{32}\b')

    for match in pattern.finditer(text):
        hash_value = match.group(0).lower()
        if validate_hash(hash_value, 'md5'):
            hashes.append(ExtractedHash(
                hash_value=hash_value,
                hash_type='md5',
                length=32,
                is_valid=True
            ))

    return hashes


def extract_sha1(text: str) -> List[ExtractedHash]:
    """Extract SHA1 hashes from text.

    Args:
        text: Text content to scan

    Returns:
        List of SHA1 hashes
    """
    hashes = []
    pattern = re.compile(r'\b[0-9a-fA-F]{40}\b')

    for match in pattern.finditer(text):
        hash_value = match.group(0).lower()
        if validate_hash(hash_value, 'sha1'):
            hashes.append(ExtractedHash(
                hash_value=hash_value,
                hash_type='sha1',
                length=40,
                is_valid=True
            ))

    return hashes


def extract_sha256(text: str) -> List[ExtractedHash]:
    """Extract SHA256 hashes from text.

    Args:
        text: Text content to scan

    Returns:
        List of SHA256 hashes
    """
    hashes = []
    pattern = re.compile(r'\b[0-9a-fA-F]{64}\b')

    for match in pattern.finditer(text):
        hash_value = match.group(0).lower()
        if validate_hash(hash_value, 'sha256'):
            hashes.append(ExtractedHash(
                hash_value=hash_value,
                hash_type='sha256',
                length=64,
                is_valid=True
            ))

    return hashes


def extract_sha512(text: str) -> List[ExtractedHash]:
    """Extract SHA512 hashes from text.

    Args:
        text: Text content to scan

    Returns:
        List of SHA512 hashes
    """
    hashes = []
    pattern = re.compile(r'\b[0-9a-fA-F]{128}\b')

    for match in pattern.finditer(text):
        hash_value = match.group(0).lower()
        if validate_hash(hash_value, 'sha512'):
            hashes.append(ExtractedHash(
                hash_value=hash_value,
                hash_type='sha512',
                length=128,
                is_valid=True
            ))

    return hashes


def validate_hash(hash_value: str, hash_type: str) -> bool:
    """Validate if hash matches expected format.

    Args:
        hash_value: Hash string to validate
        hash_type: Expected hash type

    Returns:
        True if hash is valid format
    """
    length_map = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
        'sha512': 128,
    }

    expected_length = length_map.get(hash_type.lower())
    if not expected_length:
        return False

    if len(hash_value) != expected_length:
        return False

    if not re.match(r'^[0-9a-fA-F]+$', hash_value):
        return False

    return True


def compute_file_hash(file_path: str, hash_type: str = 'sha256') -> Optional[str]:
    """Compute hash of a file.

    Args:
        file_path: Path to file
        hash_type: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Computed hash or None on error
    """
    try:
        hash_func = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
        }.get(hash_type.lower())

        if not hash_func:
            return None

        with open(file_path, 'rb') as f:
            return hash_func(f.read()).hexdigest()

    except (IOError, OSError):
        return None


def extract_hashes_by_type(text: str, hash_type: str) -> List[ExtractedHash]:
    """Extract hashes of a specific type.

    Args:
        text: Text content to scan
        hash_type: Hash type (md5, sha1, sha256, sha512)

    Returns:
        List of hashes of specified type
    """
    extractors = {
        'md5': extract_md5,
        'sha1': extract_sha1,
        'sha256': extract_sha256,
        'sha512': extract_sha512,
    }

    extractor = extractors.get(hash_type.lower())
    if not extractor:
        return []

    return extractor(text)


def get_hash_summary(hashes: List[ExtractedHash]) -> Dict[str, int]:
    """Get summary of extracted hashes by type.

    Args:
        hashes: List of extracted hashes

    Returns:
        Dictionary with count by hash type
    """
    summary = {}
    for hash_obj in hashes:
        summary[hash_obj.hash_type] = summary.get(hash_obj.hash_type, 0) + 1

    return summary