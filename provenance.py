"""Command provenance tracking for memory forensics operations"""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from database import ForensicsDatabase


class ProvenanceTracker:
    """Tracks Volatility command executions for audit trail and reproducibility"""

    def __init__(self, db: ForensicsDatabase):
        self.db = db

    async def log_command(self, dump_id: str, plugin_name: str,
                         dump_path: Path, parameters: Dict[str, Any] = None,
                         execution_time_ms: int = 0, row_count: int = 0,
                         success: bool = True, error: str = None):
        """
        Log a Volatility command execution

        Args:
            dump_id: Unique identifier for the memory dump
            plugin_name: Full plugin name (e.g., 'volatility3.plugins.windows.pslist.PsList')
            dump_path: Path to the memory dump file
            parameters: Plugin-specific parameters (e.g., {'pid': 1234})
            execution_time_ms: Execution time in milliseconds
            row_count: Number of rows returned
            success: Whether the command succeeded
            error: Error message if failed
        """
        # Build command line equivalent
        command_line = self._build_command_line(dump_path, plugin_name, parameters)

        # Serialize parameters to JSON
        params_json = json.dumps(parameters) if parameters else None

        # Store in database
        await self.db.add_command_log(
            dump_id=dump_id,
            plugin_name=plugin_name,
            command_line=command_line,
            parameters=params_json,
            execution_time_ms=execution_time_ms,
            row_count=row_count,
            success=success,
            error_message=error
        )

    def _build_command_line(self, dump_path: Path, plugin_name: str,
                           parameters: Dict[str, Any] = None) -> str:
        """
        Build vol.py command-line equivalent for reproduction

        Args:
            dump_path: Path to memory dump file
            plugin_name: Full plugin class name
            parameters: Plugin-specific parameters

        Returns:
            Command line string like: "vol.py -f dump.raw windows.pslist --pid 1234"
        """
        # Convert full plugin class name to short name
        # Example: volatility3.plugins.windows.pslist.PsList -> windows.pslist
        short_name = self._get_short_plugin_name(plugin_name)

        # Build base command
        cmd = f"vol.py -f {dump_path} {short_name}"

        # Add plugin-specific parameters
        if parameters:
            for key, val in parameters.items():
                # Skip None values
                if val is None:
                    continue

                # Format parameter
                if isinstance(val, bool):
                    if val:  # Only add flag if True
                        cmd += f" --{key}"
                else:
                    cmd += f" --{key} {val}"

        return cmd

    def _get_short_plugin_name(self, full_plugin_name: str) -> str:
        """
        Convert full plugin class name to short plugin name

        Args:
            full_plugin_name: e.g., 'volatility3.plugins.windows.pslist.PsList'

        Returns:
            Short name like 'windows.pslist'
        """
        # Split by dots
        parts = full_plugin_name.split('.')

        # Find 'plugins' in the path
        if 'plugins' in parts:
            plugins_idx = parts.index('plugins')
            # Take everything after 'plugins' except the class name
            short_parts = parts[plugins_idx + 1:-1]
            return '.'.join(short_parts)

        # Fallback: just use the full name
        return full_plugin_name

    async def get_command_history(self, dump_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get command execution history for a dump

        Args:
            dump_id: Dump identifier
            limit: Maximum number of commands to return

        Returns:
            List of command log entries
        """
        return await self.db.get_command_history(dump_id, limit)

    async def get_provenance_summary(self, dump_id: str) -> str:
        """
        Generate a formatted provenance summary

        Args:
            dump_id: Dump identifier

        Returns:
            Formatted markdown string with command history
        """
        commands = await self.get_command_history(dump_id)
        stats = await self.db.get_command_stats(dump_id)

        if not commands:
            return "No commands executed yet for this dump."

        result = "**Command Provenance**\n\n"
        result += f"Total commands executed: {stats.get('total_commands', 0)}\n"

        if stats.get('failed_commands', 0) > 0:
            result += f"Failed commands: {stats.get('failed_commands', 0)}\n"

        avg_time = stats.get('avg_execution_time')
        if avg_time:
            result += f"Average execution time: {int(avg_time)} ms\n"

        result += "\n**Volatility Commands Executed:**\n"
        for cmd in commands:
            result += f"  {cmd['command_line']}\n"
            if not cmd['success']:
                result += f"    [FAILED] {cmd.get('error_message', 'Unknown error')}\n"

        return result

    async def export_provenance_report(self, dump_id: str, output_path: Path,
                                      format: str = 'json'):
        """
        Export detailed provenance report

        Args:
            dump_id: Dump identifier
            output_path: Where to write the report
            format: 'json', 'csv', or 'txt'
        """
        commands = await self.get_command_history(dump_id, limit=1000)
        stats = await self.db.get_command_stats(dump_id)

        if format == 'json':
            data = {
                'dump_id': dump_id,
                'statistics': stats,
                'commands': commands
            }
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        elif format == 'csv':
            import csv
            with open(output_path, 'w', newline='') as f:
                if commands:
                    writer = csv.DictWriter(f, fieldnames=commands[0].keys())
                    writer.writeheader()
                    writer.writerows(commands)

        elif format == 'txt':
            with open(output_path, 'w') as f:
                f.write(f"Provenance Report for {dump_id}\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Total Commands: {stats.get('total_commands', 0)}\n")
                f.write(f"Failed Commands: {stats.get('failed_commands', 0)}\n")
                f.write(f"Avg Execution Time: {int(stats.get('avg_execution_time', 0))} ms\n\n")
                f.write("Commands:\n")
                f.write("-" * 60 + "\n")
                for cmd in commands:
                    f.write(f"\n[{cmd['executed_at']}]\n")
                    f.write(f"Plugin: {cmd['plugin_name']}\n")
                    f.write(f"Command: {cmd['command_line']}\n")
                    f.write(f"Time: {cmd.get('execution_time_ms', 0)} ms\n")
                    f.write(f"Results: {cmd.get('row_count', 0)} rows\n")
                    if not cmd['success']:
                        f.write(f"Status: FAILED - {cmd.get('error_message')}\n")
                    f.write("-" * 60 + "\n")
