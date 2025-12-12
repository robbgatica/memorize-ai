"""Enhanced anomaly detection for suspicious processes"""
import difflib
from typing import List, Dict, Any, Optional, Set
from database import ForensicsDatabase


class AnomalyDetector:
    """Enhanced anomaly detection for suspicious processes and behavior"""

    def __init__(self, db: ForensicsDatabase):
        self.db = db

        # Known-good parent-child relationships
        self.expected_parents = {
            'services.exe': {'svchost.exe', 'dllhost.exe', 'taskhost.exe', 'wuauclt.exe', 'spoolsv.exe'},
            'explorer.exe': {'chrome.exe', 'firefox.exe', 'notepad.exe', 'cmd.exe', 'powershell.exe',
                           'iexplore.exe', 'msedge.exe', 'OneDrive.exe'},
            'svchost.exe': {'wuauclt.exe', 'SearchIndexer.exe', 'RuntimeBroker.exe', 'taskhostw.exe'},
            'winlogon.exe': {'userinit.exe', 'LogonUI.exe'},
            'userinit.exe': {'explorer.exe'},
            'smss.exe': {'csrss.exe', 'wininit.exe'},
            'wininit.exe': {'services.exe', 'lsass.exe'},
        }

        # Processes that should only have one instance
        self.single_instance_processes = {
            'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'winlogon.exe'
        }

        # Known legitimate paths for Windows processes
        self.legitimate_paths = [
            r'C:\Windows\System32',
            r'C:\Windows\SysWOW64',
            r'C:\Windows\explorer.exe',
        ]

        # Suspicious paths
        self.suspicious_paths = [
            r'\Temp\\',
            r'\AppData\Local\Temp',
            r'\Users\Public',
            r'\ProgramData',
            r'C:\$Recycle.Bin',
        ]

        # Common process names (for typosquatting detection)
        self.common_names = {
            'svchost.exe', 'lsass.exe', 'csrss.exe', 'explorer.exe',
            'services.exe', 'smss.exe', 'winlogon.exe', 'wininit.exe',
            'spoolsv.exe', 'taskhost.exe', 'dwm.exe', 'conhost.exe'
        }

    async def detect_anomalies(self, dump_id: str) -> List[Dict[str, Any]]:
        """
        Detect various process anomalies

        Args:
            dump_id: Dump identifier

        Returns:
            List of anomaly findings
        """
        anomalies = []
        processes = await self.db.get_processes(dump_id)

        # Build process map
        proc_map = {p['pid']: p for p in processes}

        for proc in processes:
            # Check parent relationship
            parent_anomaly = self._check_parent_anomaly(proc, proc_map)
            if parent_anomaly:
                anomalies.append(parent_anomaly)

            # Check for misspelled names
            name_anomaly = self._check_misspelled_name(proc)
            if name_anomaly:
                anomalies.append(name_anomaly)

            # Check execution path
            path_anomaly = self._check_unusual_path(proc)
            if path_anomaly:
                anomalies.append(path_anomaly)

        # Check for duplicate single-instance processes
        duplicate_anomalies = self._check_duplicate_instances(processes)
        anomalies.extend(duplicate_anomalies)

        return anomalies

    def _check_parent_anomaly(self, proc: Dict[str, Any],
                              proc_map: Dict[int, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if parent process is unexpected"""
        proc_name = proc.get('name', '').lower()
        ppid = proc.get('ppid')

        if not ppid or ppid not in proc_map:
            return None

        parent = proc_map[ppid]
        parent_name = parent.get('name', '').lower()

        # Check expected parent-child relationships
        # Look for child processes with specific expected parents
        for expected_parent, expected_children in self.expected_parents.items():
            if proc_name in expected_children:
                if parent_name != expected_parent:
                    return {
                        'type': 'unexpected_parent',
                        'severity': 'high',
                        'pid': proc['pid'],
                        'process': proc_name,
                        'parent_pid': ppid,
                        'parent_name': parent_name,
                        'expected_parent': expected_parent,
                        'description': f"{proc_name} (PID {proc['pid']}) has unexpected parent {parent_name} (expected {expected_parent})"
                    }

        # Check for suspicious parent-child combinations
        if parent_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']:
            # Office apps spawning shells is suspicious
            if proc_name in ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']:
                return {
                    'type': 'suspicious_parent_child',
                    'severity': 'critical',
                    'pid': proc['pid'],
                    'process': proc_name,
                    'parent_pid': ppid,
                    'parent_name': parent_name,
                    'description': f"{proc_name} spawned by {parent_name} (possible macro/exploit)"
                }

        return None

    def _check_misspelled_name(self, proc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect potential typosquatting of common process names"""
        proc_name = proc.get('name', '').lower()

        if not proc_name:
            return None

        for common in self.common_names:
            if proc_name == common:
                continue

            # Check similarity (e.g., 'svch0st.exe' vs 'svchost.exe')
            similarity = difflib.SequenceMatcher(None, proc_name, common).ratio()

            if similarity > 0.85 and proc_name != common:
                return {
                    'type': 'misspelled_name',
                    'severity': 'high',
                    'pid': proc['pid'],
                    'process': proc_name,
                    'similar_to': common,
                    'similarity': round(similarity, 3),
                    'description': f"Process name '{proc_name}' (PID {proc['pid']}) is similar to '{common}' (possible typosquatting)"
                }

        return None

    def _check_unusual_path(self, proc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if process is running from unusual location"""
        proc_path = proc.get('path', '')
        proc_name = proc.get('name', '').lower()

        if not proc_path or proc_path in ['', 'N/A', 'None']:
            return None

        # Windows system processes should be in System32/SysWOW64
        if proc_name in self.common_names:
            is_legitimate = any(legit_path in proc_path for legit_path in self.legitimate_paths)

            if not is_legitimate:
                return {
                    'type': 'unusual_path',
                    'severity': 'critical',
                    'pid': proc['pid'],
                    'process': proc_name,
                    'path': proc_path,
                    'description': f"System process {proc_name} (PID {proc['pid']}) running from unusual path: {proc_path}"
                }

        # Check for execution from suspicious paths
        for suspicious_path in self.suspicious_paths:
            if suspicious_path in proc_path:
                return {
                    'type': 'suspicious_path',
                    'severity': 'medium',
                    'pid': proc['pid'],
                    'process': proc_name,
                    'path': proc_path,
                    'description': f"Process {proc_name} (PID {proc['pid']}) running from suspicious location: {proc_path}"
                }

        return None

    def _check_duplicate_instances(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for multiple instances of single-instance processes"""
        anomalies = []

        # Count instances of each process
        process_counts = {}
        for proc in processes:
            name = proc.get('name', '').lower()
            if name not in process_counts:
                process_counts[name] = []
            process_counts[name].append(proc)

        # Check single-instance processes
        for proc_name in self.single_instance_processes:
            if proc_name in process_counts and len(process_counts[proc_name]) > 1:
                pids = [p['pid'] for p in process_counts[proc_name]]
                anomalies.append({
                    'type': 'duplicate_instance',
                    'severity': 'high',
                    'process': proc_name,
                    'count': len(pids),
                    'pids': pids,
                    'description': f"Multiple instances of {proc_name} detected (PIDs: {', '.join(map(str, pids))})"
                })

        return anomalies

    async def get_anomaly_report(self, dump_id: str) -> str:
        """
        Generate formatted anomaly report

        Args:
            dump_id: Dump identifier

        Returns:
            Formatted markdown string
        """
        anomalies = await self.detect_anomalies(dump_id)

        if not anomalies:
            return f"**Anomaly Detection - {dump_id}**\n\nNo anomalies detected. All processes appear normal."

        # Group by severity
        critical = [a for a in anomalies if a.get('severity') == 'critical']
        high = [a for a in anomalies if a.get('severity') == 'high']
        medium = [a for a in anomalies if a.get('severity') == 'medium']

        result = f"**Anomaly Detection - {dump_id}**\n\n"
        result += f"Total Anomalies: {len(anomalies)}\n"
        result += f"- Critical: {len(critical)}\n"
        result += f"- High: {len(high)}\n"
        result += f"- Medium: {len(medium)}\n\n"

        if critical:
            result += "**[CRITICAL] Anomalies:**\n"
            for anomaly in critical:
                result += f"- {anomaly['description']}\n"
            result += "\n"

        if high:
            result += "**[HIGH] Severity Anomalies:**\n"
            for anomaly in high:
                result += f"- {anomaly['description']}\n"
            result += "\n"

        if medium:
            result += "**[MEDIUM] Severity Anomalies:**\n"
            for anomaly in medium:
                result += f"- {anomaly['description']}\n"

        return result
