"""Timeline generation from forensic artifacts"""
import json
import csv
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from database import ForensicsDatabase


@dataclass
class TimelineEvent:
    """Unified timeline event"""
    timestamp: datetime
    event_type: str  # 'process_created', 'process_exited', 'network_connection'
    description: str
    source: str  # 'process', 'network', 'memory_region'
    pid: Optional[int] = None
    process_name: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    is_suspicious: bool = False

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat() if self.timestamp else None
        return d


class TimelineGenerator:
    """Generate chronological timeline from forensic artifacts"""

    def __init__(self, db: ForensicsDatabase):
        self.db = db

    async def generate_timeline(self, dump_id: str,
                               include_types: List[str] = None,
                               suspicious_only: bool = False) -> List[TimelineEvent]:
        """
        Generate unified timeline from all sources

        Args:
            dump_id: Dump identifier
            include_types: Filter to specific event types
            suspicious_only: Only include suspicious events

        Returns:
            List of timeline events sorted chronologically
        """
        events = []

        # Process creation events
        processes = await self.db.get_processes(dump_id)
        for proc in processes:
            # Skip non-suspicious if filtering
            if suspicious_only and not proc.get('is_suspicious'):
                continue

            # Process creation
            if proc.get('create_time'):
                timestamp = self._parse_timestamp(proc['create_time'])
                if timestamp:
                    flags = []
                    if proc.get('is_hidden'):
                        flags.append('HIDDEN')
                    if proc.get('is_suspicious'):
                        flags.append('SUSPICIOUS')
                    flag_str = f" [{', '.join(flags)}]" if flags else ""

                    events.append(TimelineEvent(
                        timestamp=timestamp,
                        event_type='process_created',
                        description=f"Process {proc.get('name', 'Unknown')} (PID {proc['pid']}) created{flag_str}",
                        source='process',
                        pid=proc['pid'],
                        process_name=proc.get('name'),
                        details=proc,
                        is_suspicious=proc.get('is_suspicious', False)
                    ))

            # Process exit
            if proc.get('exit_time') and proc['exit_time'] not in ['', 'N/A', 'None']:
                timestamp = self._parse_timestamp(proc['exit_time'])
                if timestamp:
                    events.append(TimelineEvent(
                        timestamp=timestamp,
                        event_type='process_exited',
                        description=f"Process {proc.get('name', 'Unknown')} (PID {proc['pid']}) exited",
                        source='process',
                        pid=proc['pid'],
                        process_name=proc.get('name'),
                        details=proc,
                        is_suspicious=proc.get('is_suspicious', False)
                    ))

        # Note: Network connections from netscan don't have timestamps
        # They represent the state at the time of the dump
        # We could add them with dump timestamp if needed

        # Sort chronologically
        events.sort(key=lambda e: e.timestamp)

        # Filter by event types if specified
        if include_types:
            events = [e for e in events if e.event_type in include_types]

        return events

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """
        Parse timestamp string to datetime object

        Args:
            timestamp_str: Timestamp string from Volatility

        Returns:
            datetime object or None if parsing fails
        """
        if not timestamp_str or timestamp_str in ['N/A', 'None', '']:
            return None

        # Try different formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
        ]

        # Clean the string
        ts = str(timestamp_str).strip()

        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue

        # Try ISO format
        try:
            return datetime.fromisoformat(ts)
        except:
            pass

        return None

    async def export_timeline_json(self, dump_id: str, output_path: Path,
                                   **kwargs) -> Dict[str, Any]:
        """
        Export timeline to JSON format

        Args:
            dump_id: Dump identifier
            output_path: Output file path
            **kwargs: Additional arguments for generate_timeline

        Returns:
            Export statistics
        """
        events = await self.generate_timeline(dump_id, **kwargs)

        data = {
            'dump_id': dump_id,
            'generated_at': datetime.now().isoformat(),
            'event_count': len(events),
            'timeline': [e.to_dict() for e in events]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return {
            'format': 'JSON',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size,
            'event_count': len(events)
        }

    async def export_timeline_csv(self, dump_id: str, output_path: Path,
                                  **kwargs) -> Dict[str, Any]:
        """
        Export timeline to CSV format

        Args:
            dump_id: Dump identifier
            output_path: Output file path
            **kwargs: Additional arguments for generate_timeline

        Returns:
            Export statistics
        """
        events = await self.generate_timeline(dump_id, **kwargs)

        with open(output_path, 'w', newline='') as f:
            if events:
                fieldnames = ['timestamp', 'event_type', 'description', 'source',
                             'pid', 'process_name', 'is_suspicious']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for event in events:
                    writer.writerow({
                        'timestamp': event.timestamp.isoformat() if event.timestamp else '',
                        'event_type': event.event_type,
                        'description': event.description,
                        'source': event.source,
                        'pid': event.pid or '',
                        'process_name': event.process_name or '',
                        'is_suspicious': event.is_suspicious
                    })

        return {
            'format': 'CSV',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size,
            'event_count': len(events)
        }

    async def export_timeline_text(self, dump_id: str, output_path: Path,
                                   **kwargs) -> Dict[str, Any]:
        """
        Export timeline to human-readable text format

        Args:
            dump_id: Dump identifier
            output_path: Output file path
            **kwargs: Additional arguments for generate_timeline

        Returns:
            Export statistics
        """
        events = await self.generate_timeline(dump_id, **kwargs)

        with open(output_path, 'w') as f:
            f.write(f"Timeline for {dump_id}\n")
            f.write("=" * 80 + "\n\n")

            if not events:
                f.write("No timeline events found.\n")
            else:
                for event in events:
                    timestamp_str = event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if event.timestamp else 'Unknown'
                    suspicious_flag = " [SUSPICIOUS]" if event.is_suspicious else ""
                    f.write(f"{timestamp_str} | {event.event_type.upper():20} | {event.description}{suspicious_flag}\n")

        return {
            'format': 'TEXT',
            'output_path': str(output_path),
            'file_size': output_path.stat().st_size,
            'event_count': len(events)
        }

    async def get_timeline_summary(self, dump_id: str) -> str:
        """
        Generate formatted timeline summary for display

        Args:
            dump_id: Dump identifier

        Returns:
            Formatted markdown string
        """
        events = await self.generate_timeline(dump_id)

        if not events:
            return f"No timeline events available for {dump_id}"

        result = f"**Timeline - {dump_id}**\n\n"
        result += f"Total Events: {len(events)}\n\n"

        # Show first 50 events
        for event in events[:50]:
            timestamp_str = event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if event.timestamp else 'Unknown'
            suspicious_flag = " [SUSPICIOUS]" if event.is_suspicious else ""
            result += f"{timestamp_str} | {event.event_type.upper()} | {event.description}{suspicious_flag}\n"

        if len(events) > 50:
            result += f"\n... and {len(events) - 50} more events\n"
            result += f"\nUse export_timeline to save full timeline to file.\n"

        return result
