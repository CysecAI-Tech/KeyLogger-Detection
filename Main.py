#!/usr/bin/env python3
"""
Keylogger Detection and Prevention System
Educational tool for detecting suspicious keylogging behavior
"""

import psutil
import os
import time
import hashlib
import winreg
import threading
from collections import defaultdict
import json
from datetime import datetime

class KeyloggerDetector:
    def __init__(self):
        self.suspicious_processes = []
        self.monitoring = False
        self.alerts = []
        self.process_monitor = defaultdict(dict)
        
        # Common keylogger indicators
        self.suspicious_keywords = [
            'keylog', 'keystroke', 'keyboard', 'capture',
            'monitor', 'spy', 'stealth', 'hidden'
        ]
        
        self.suspicious_files = [
            'key_log.txt', 'keylog.txt', 'keys.txt',
            'passwords.txt', 'clipboard.txt', 'audio.wav',
            'screenshot.png', 'webcam.png'
        ]
        
        self.hook_dlls = [
            'user32.dll', 'kernel32.dll', 'ntdll.dll'
        ]
    
    def scan_running_processes(self):
        """Scan for suspicious running processes"""
        print("🔍 Scanning running processes...")
        suspicious_found = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                
                # Check process name for suspicious keywords
                for keyword in self.suspicious_keywords:
                    if keyword in proc_name:
                        suspicious_found.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'reason': f'Suspicious keyword: {keyword}',
                            'cmdline': proc_info.get('cmdline', [])
                        })
                        break
                
                # Check for processes with network connections (potential data exfiltration)
                connections = proc_info.get('connections', [])
                if connections and 'python' in proc_name:
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            suspicious_found.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'reason': f'Network connection to {conn.raddr}',
                                'cmdline': proc_info.get('cmdline', [])
                            })
                            break
                            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious_found
    
    def scan_file_system(self, paths_to_scan=None):
        """Scan for suspicious files that keyloggers might create"""
        if paths_to_scan is None:
            paths_to_scan = [
                os.path.expanduser('~'),  # User home directory
                'C:\\Windows\\Temp',      # Common temp directory
                'C:\\Temp',
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', '')
            ]
        
        print("📁 Scanning file system for suspicious files...")
        suspicious_files_found = []
        
        for base_path in paths_to_scan:
            if not os.path.exists(base_path):
                continue
                
            try:
                for root, dirs, files in os.walk(base_path):
                    # Skip system directories to avoid false positives
                    if any(skip in root.lower() for skip in ['system32', 'program files', 'windows']):
                        continue
                        
                    for file in files:
                        file_lower = file.lower()
                        
                        # Check for suspicious file names
                        for suspicious_file in self.suspicious_files:
                            if suspicious_file in file_lower:
                                file_path = os.path.join(root, file)
                                try:
                                    file_size = os.path.getsize(file_path)
                                    mod_time = os.path.getmtime(file_path)
                                    
                                    suspicious_files_found.append({
                                        'path': file_path,
                                        'size': file_size,
                                        'modified': datetime.fromtimestamp(mod_time),
                                        'reason': f'Matches suspicious pattern: {suspicious_file}'
                                    })
                                except OSError:
                                    continue
                                break
                                
            except PermissionError:
                continue
        
        return suspicious_files_found
    
    def check_registry_entries(self):
        """Check Windows registry for suspicious entries"""
        print("📋 Checking registry for suspicious entries...")
        suspicious_entries = []
        
        # Check common autostart locations
        autostart_keys = [
            (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ]
        
        for hkey, subkey in autostart_keys:
            try:
                key = winreg.OpenKey(hkey, subkey)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        
                        # Check if value contains suspicious keywords
                        value_lower = str(value).lower()
                        name_lower = str(name).lower()
                        
                        for keyword in self.suspicious_keywords:
                            if keyword in value_lower or keyword in name_lower:
                                suspicious_entries.append({
                                    'key': f"{hkey}\\{subkey}",
                                    'name': name,
                                    'value': value,
                                    'reason': f'Contains suspicious keyword: {keyword}'
                                })
                                break
                        
                        i += 1
                    except WindowsError:
                        break
                        
                winreg.CloseKey(key)
            except WindowsError:
                continue
        
        return suspicious_entries
    
    def monitor_keyboard_hooks(self):
        """Monitor for processes that might be installing keyboard hooks"""
        print("⌨️ Monitoring for keyboard hooks...")
        hook_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                # Check if process is using suspicious DLLs
                proc_name = proc.info['name'].lower()
                
                # Skip system processes
                if proc_name in ['explorer.exe', 'winlogon.exe', 'csrss.exe']:
                    continue
                
                # Check memory usage patterns (keyloggers often have low memory usage)
                memory_mb = proc.info['memory_info'].rss / 1024 / 1024
                
                if memory_mb < 50 and 'python' in proc_name:  # Suspicious low memory Python process
                    hook_processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'memory_mb': round(memory_mb, 2),
                        'reason': 'Low memory Python process (potential keylogger)'
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return hook_processes
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*60)
        print("🛡️  KEYLOGGER DETECTION REPORT")
        print("="*60)
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Scan for suspicious processes
        suspicious_procs = self.scan_running_processes()
        print(f"📊 SUSPICIOUS PROCESSES: {len(suspicious_procs)} found")
        for proc in suspicious_procs:
            print(f"  ⚠️  PID {proc['pid']}: {proc['name']}")
            print(f"     Reason: {proc['reason']}")
            if proc['cmdline']:
                print(f"     Command: {' '.join(proc['cmdline'])}")
            print()
        
        # Scan file system
        suspicious_files = self.scan_file_system()
        print(f"📁 SUSPICIOUS FILES: {len(suspicious_files)} found")
        for file_info in suspicious_files[:10]:  # Limit to first 10
            print(f"  ⚠️  {file_info['path']}")
            print(f"     Size: {file_info['size']} bytes")
            print(f"     Modified: {file_info['modified']}")
            print(f"     Reason: {file_info['reason']}")
            print()
        
        # Check registry
        try:
            suspicious_reg = self.check_registry_entries()
            print(f"📋 SUSPICIOUS REGISTRY ENTRIES: {len(suspicious_reg)} found")
            for entry in suspicious_reg:
                print(f"  ⚠️  {entry['name']}")
                print(f"     Location: {entry['key']}")
                print(f"     Value: {entry['value']}")
                print(f"     Reason: {entry['reason']}")
                print()
        except Exception as e:
            print(f"❌ Could not check registry: {e}")
        
        # Monitor hooks
        hook_procs = self.monitor_keyboard_hooks()
        print(f"⌨️  POTENTIAL HOOK PROCESSES: {len(hook_procs)} found")
        for proc in hook_procs:
            print(f"  ⚠️  PID {proc['pid']}: {proc['name']}")
            print(f"     Memory: {proc['memory_mb']} MB")
            print(f"     Reason: {proc['reason']}")
            print()
        
        # Security recommendations
        print("🔒 SECURITY RECOMMENDATIONS:")
        print("  • Run full antivirus scan")
        print("  • Update all software and OS")
        print("  • Check browser extensions")
        print("  • Monitor network traffic")
        print("  • Enable Windows Defender real-time protection")
        print("  • Use virtual keyboard for sensitive input")
        print("  • Regular system monitoring")
        print()
        
        # Calculate risk score
        total_threats = len(suspicious_procs) + len(suspicious_files) + len(hook_procs)
        if total_threats == 0:
            risk_level = "LOW ✅"
        elif total_threats < 3:
            risk_level = "MEDIUM ⚠️"
        else:
            risk_level = "HIGH ❌"
        
        print(f"🎯 RISK ASSESSMENT: {risk_level}")
        print(f"   Total suspicious items: {total_threats}")
        
        return {
            'suspicious_processes': suspicious_procs,
            'suspicious_files': suspicious_files,
            'hook_processes': hook_procs,
            'risk_level': risk_level,
            'total_threats': total_threats
        }
    
    def real_time_monitor(self, duration=60):
        """Real-time monitoring for suspicious activity"""
        print(f"🔄 Starting real-time monitoring for {duration} seconds...")
        start_time = time.time()
        
        initial_processes = set(p.info['pid'] for p in psutil.process_iter(['pid']))
        
        while time.time() - start_time < duration:
            try:
                current_processes = set(p.info['pid'] for p in psutil.process_iter(['pid']))
                new_processes = current_processes - initial_processes
                
                for pid in new_processes:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name().lower()
                        
                        # Check if new process is suspicious
                        for keyword in self.suspicious_keywords:
                            if keyword in proc_name:
                                print(f"🚨 ALERT: New suspicious process detected!")
                                print(f"   PID: {pid}, Name: {proc.name()}")
                                print(f"   Reason: Contains keyword '{keyword}'")
                                break
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                initial_processes = current_processes
                time.sleep(5)  # Check every 5 seconds
                
            except KeyboardInterrupt:
                print("\n⏹️  Monitoring stopped by user")
                break
        
        print("✅ Real-time monitoring completed")

def main():
    detector = KeyloggerDetector()
    
    print("🛡️  Keylogger Detection and Prevention System")
    print("=" * 50)
    
    while True:
        print("\n1. Quick Scan")
        print("2. Full System Scan")
        print("3. Real-time Monitor")
        print("4. Check Specific Directory")
        print("5. Generate Report")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            print("\n🔍 Running quick scan...")
            procs = detector.scan_running_processes()
            if procs:
                print(f"⚠️  Found {len(procs)} suspicious processes")
                for proc in procs:
                    print(f"   • {proc['name']} (PID: {proc['pid']})")
            else:
                print("✅ No suspicious processes found")
        
        elif choice == '2':
            detector.generate_report()
        
        elif choice == '3':
            try:
                duration = int(input("Enter monitoring duration in seconds (default 60): ") or "60")
                detector.real_time_monitor(duration)
            except ValueError:
                print("❌ Invalid duration")
        
        elif choice == '4':
            path = input("Enter directory path to scan: ").strip()
            if os.path.exists(path):
                files = detector.scan_file_system([path])
                if files:
                    print(f"⚠️  Found {len(files)} suspicious files")
                    for file_info in files:
                        print(f"   • {file_info['path']}")
                else:
                    print("✅ No suspicious files found")
            else:
                print("❌ Path does not exist")
        
        elif choice == '5':
            report = detector.generate_report()
            
            # Save report to file
            report_file = f"keylogger_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"📄 Report saved to: {report_file}")
        
        elif choice == '6':
            print("👋 Stay secure!")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    print("⚠️  Note: This tool requires administrator privileges for full functionality")
    print("   Run as administrator for complete registry and system access")
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting... Stay secure!")
    except Exception as e:
        print(f"❌ Error: {e}")
