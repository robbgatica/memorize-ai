"""Memory and process extraction utilities"""
from pathlib import Path
from typing import Dict, Any, Optional
from database import ForensicsDatabase
from volatility_handler import VolatilityHandler
from hashing import calculate_hashes


class MemoryExtractor:
    """Extract processes and memory regions from dumps"""

    def __init__(self, vol_handler: VolatilityHandler, db: ForensicsDatabase, dump_id: str):
        self.vol = vol_handler
        self.db = db
        self.dump_id = dump_id

    async def extract_process_info(self, pid: int, output_dir: Path) -> Dict[str, Any]:
        """
        Extract detailed process information to file

        Note: This extracts process INFORMATION, not the actual memory
        Full memory extraction requires additional Volatility plugins

        Args:
            pid: Process ID
            output_dir: Output directory

        Returns:
            Extraction info dictionary
        """
        import json

        # Get process info from database
        process = await self.db.get_process_by_pid(self.dump_id, pid)
        if not process:
            raise ValueError(f"Process {pid} not found in dump")

        # Get additional details
        cmdlines = await self.vol.get_cmdline(pid)
        dlls = await self.vol.get_dlls(pid)
        connections = await self.db.get_network_connections(self.dump_id, pid)
        memory_regions = await self.db.get_suspicious_memory_regions(self.dump_id, pid)

        # Compile comprehensive process info
        process_info = {
            'dump_id': self.dump_id,
            'pid': pid,
            'basic_info': process,
            'command_line': cmdlines[0] if cmdlines else None,
            'loaded_dlls': dlls,
            'network_connections': connections,
            'suspicious_memory_regions': memory_regions
        }

        # Write to JSON file
        output_path = output_dir / f"process_{pid}_info.json"
        with open(output_path, 'w') as f:
            json.dump(process_info, f, indent=2, default=str)

        # Calculate hash
        hashes = await calculate_hashes(output_path, ['sha256'])

        # Track extraction
        await self.db.add_extracted_file(
            dump_id=self.dump_id,
            extraction_type='process_info',
            source_pid=pid,
            output_path=str(output_path),
            file_size=output_path.stat().st_size,
            file_hash_sha256=hashes['sha256']
        )

        return {
            'type': 'process_info',
            'pid': pid,
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size,
            'sha256': hashes['sha256'],
            'dll_count': len(dlls),
            'connection_count': len(connections),
            'suspicious_region_count': len(memory_regions)
        }

    async def list_extractions(self) -> Dict[str, Any]:
        """
        List all previous extractions for this dump

        Returns:
            Dictionary with extraction history
        """
        extractions = await self.db.get_extracted_files(self.dump_id)

        return {
            'dump_id': self.dump_id,
            'extraction_count': len(extractions),
            'extractions': extractions
        }

    def get_extraction_instructions(self) -> str:
        """
        Provide instructions for full memory extraction using Volatility CLI

        Returns:
            Instruction text
        """
        return """
**Full Memory Extraction Instructions**

To extract full process memory, use Volatility 3 CLI directly:

1. **Extract process memory:**
   ```
   vol.py -f dump.raw windows.memmap --pid <PID> --dump
   ```

2. **Extract process executable:**
   ```
   vol.py -f dump.raw windows.dumpfiles --pid <PID>
   ```

3. **Extract specific memory region:**
   ```
   vol.py -f dump.raw windows.vadinfo --pid <PID> --dump
   ```

These commands will create binary files that can be analyzed with:
- Hex editors
- Strings extraction
- Malware analysis tools
- Debuggers

Note: The current MCP server extracts process INFORMATION (metadata, DLLs,
connections) rather than raw memory to avoid generating large binary files.
"""


async def create_extractor(dump_id: str, vol_handler: VolatilityHandler,
                           db: ForensicsDatabase) -> MemoryExtractor:
    """
    Factory function to create MemoryExtractor

    Args:
        dump_id: Dump identifier
        vol_handler: VolatilityHandler instance
        db: Database instance

    Returns:
        MemoryExtractor instance
    """
    return MemoryExtractor(vol_handler, db, dump_id)
