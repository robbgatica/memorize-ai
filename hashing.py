"""File hashing utilities for memory dump integrity verification"""
import hashlib
import asyncio
from pathlib import Path
from typing import Dict, List
from database import ForensicsDatabase


async def calculate_hashes(file_path: Path,
                          algorithms: List[str] = None) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file asynchronously

    Args:
        file_path: Path to file to hash
        algorithms: List of hash algorithms (default: ['md5', 'sha1', 'sha256'])

    Returns:
        Dictionary of algorithm -> hexdigest mapping

    Example:
        {'md5': 'd41d8cd...', 'sha1': 'da39a3e...', 'sha256': 'e3b0c44...'}
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256']

    # Create hashers for each algorithm
    hashers = {alg: hashlib.new(alg) for alg in algorithms}

    # Use 8MB chunks for performance with large memory dumps
    chunk_size = 8 * 1024 * 1024

    # Run hash calculation in executor to avoid blocking
    def _calculate():
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)

        return {alg: hasher.hexdigest() for alg, hasher in hashers.items()}

    # Run in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _calculate)

    return result


async def get_or_calculate_hashes(db: ForensicsDatabase, dump_id: str,
                                 dump_path: Path) -> Dict[str, str]:
    """
    Get cached hashes or calculate if not available

    Args:
        db: Database instance
        dump_id: Dump identifier
        dump_path: Path to dump file

    Returns:
        Dictionary of hashes
    """
    # Check database cache first
    cached_hashes = await db.get_dump_hashes(dump_id)

    if cached_hashes:
        return cached_hashes

    # Calculate hashes
    hashes = await calculate_hashes(dump_path)

    # Store in database
    await db.store_dump_hashes(dump_id, hashes)

    return hashes


def format_hashes(hashes: Dict[str, str]) -> str:
    """
    Format hashes for display

    Args:
        hashes: Dictionary of algorithm -> digest mapping

    Returns:
        Formatted markdown string
    """
    result = "**File Hashes:**\n"

    if 'md5' in hashes:
        result += f"- MD5: {hashes['md5']}\n"
    if 'sha1' in hashes:
        result += f"- SHA1: {hashes['sha1']}\n"
    if 'sha256' in hashes:
        result += f"- SHA256: {hashes['sha256']}\n"

    return result
