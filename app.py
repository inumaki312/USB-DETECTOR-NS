from flask import Flask, render_template, request, redirect, url_for, session
import subprocess
import platform
from datetime import datetime, timedelta
from encrypt import setup_gpg

# --- CONFIG ---
ADMIN_PASSWORD = "usbdetector"  
SESSION_TIMEOUT = 30  # Session timeout in seconds

# Known malicious USB vendor IDs
MALICIOUS_VENDORS = {
    '0c45', '1d34', '1a86', '0480', '04e8',
    '0781', '0951', '18d1', '04f2', '0bda'
}

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for session management
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT)
setup_gpg()

# Track USB port state
ports_enabled = False

def get_usb_devices():
    """Get USB devices based on the operating system"""
    system = platform.system().lower()
    
    if system == 'windows':
        try:
            # Get external USB devices only
            ps_commands = [
                # Get external USB storage devices only
                """Get-WmiObject Win32_DiskDrive | Where-Object {
                    $_.InterfaceType -eq "USB" -and 
                    $_.MediaType -eq "External hard disk media"
                } | ForEach-Object {
                    $disk = $_
                    $props = @{
                        FriendlyName = $disk.Caption
                        Status = if ($disk.Status) { $disk.Status } else { "Connected" }
                        InstanceId = $disk.PNPDeviceID
                    }
                    New-Object PSObject -Property $props
                } | Format-List""",
                
                # Get USB devices (excluding internal components)
                """Get-PnpDevice | Where-Object { 
                    $_.Class -eq 'USB' -and 
                    $_.FriendlyName -notmatch 'Host Controller|Root Hub|Composite Device|Enhanced Host Controller|USB Input Device' -and
                    $_.Status -eq 'OK'
                } | Select-Object Status, Class, FriendlyName, InstanceId | Format-List"""
            ]
            
            all_devices = []
            for cmd in ps_commands:
                result = subprocess.run(['powershell', '-Command', cmd], 
                                     capture_output=True, 
                                     text=True)
                if result.stdout.strip():
                    all_devices.append(result.stdout)
            
            # Clean up the output to remove empty entries
            cleaned_output = "\n".join(all_devices)
            if not cleaned_output.strip():
                return "No external USB devices detected."
            return cleaned_output
        except Exception as e:
            return f"Error getting USB devices: {str(e)}"
    else:
        # Linux systems
        try:
            return subprocess.getoutput("lsusb")
        except Exception as e:
            return f"Error getting USB devices: {str(e)}"

# --- USB DISABLER FUNCTION ---
def disable_usb_ports():
    system = platform.system().lower()
    if system == 'windows':
        try:
            # Windows command to disable external USB devices only
            ps_commands = [
                """Get-PnpDevice | Where-Object {
                    $_.Class -eq 'USB' -and 
                    $_.FriendlyName -notmatch 'Host Controller|Root Hub|Composite Device|Enhanced Host Controller|USB Input Device'
                } | Disable-PnpDevice -Confirm:$false""",
                
                """Get-WmiObject Win32_DiskDrive | Where-Object {
                    $_.InterfaceType -eq "USB" -and 
                    $_.MediaType -eq "External hard disk media"
                } | ForEach-Object {
                    $disk = $_
                    $disk.Disable()
                }"""
            ]
            for cmd in ps_commands:
                subprocess.run(['powershell', '-Command', cmd], capture_output=True)
        except Exception as e:
            print(f"Error disabling USB ports: {str(e)}")
    else:
        # Linux systems
        subprocess.call(["sudo", "modprobe", "-r", "usb_storage"])

def enable_usb_ports():
    system = platform.system().lower()
    if system == 'windows':
        try:
            # Windows command to enable external USB devices only
            ps_commands = [
                """Get-PnpDevice | Where-Object {
                    $_.Class -eq 'USB' -and 
                    $_.FriendlyName -notmatch 'Host Controller|Root Hub|Composite Device|Enhanced Host Controller|USB Input Device'
                } | Enable-PnpDevice -Confirm:$false""",
                
                """Get-WmiObject Win32_DiskDrive | Where-Object {
                    $_.InterfaceType -eq "USB" -and 
                    $_.MediaType -eq "External hard disk media"
                } | ForEach-Object {
                    $disk = $_
                    $disk.Enable()
                }"""
            ]
            for cmd in ps_commands:
                subprocess.run(['powershell', '-Command', cmd], capture_output=True)
        except Exception as e:
            print(f"Error enabling USB ports: {str(e)}")
    else:
        # Linux systems
        subprocess.call(["sudo", "modprobe", "usb_storage"])

# Disable on start
disable_usb_ports()

# Initialize log counter
log_counter = 0
try:
    with open('usb.log', 'r') as f:
        log_counter = sum(1 for _ in f)
except FileNotFoundError:
    pass

def detect_malicious(device_output):
    malicious = []
    system = platform.system().lower()
    
    if system == 'windows':
        # Parse Windows PowerShell output
        devices = device_output.split('\n\n')
        for device in devices:
            if 'InstanceId' in device:
                try:
                    # Extract VID from InstanceId
                    instance_id = [line for line in device.split('\n') if 'InstanceId' in line][0]
                    if 'VID_' in instance_id:
                        vendor_id = instance_id.split('VID_')[1][:4].lower()
                        if vendor_id in MALICIOUS_VENDORS:
                            friendly_name = [line for line in device.split('\n') if 'FriendlyName' in line]
                            device_info = friendly_name[0].split(': ')[1] if friendly_name else 'Unknown Device'
                            malicious.append(f"{vendor_id}: {device_info}")
                except (IndexError, ValueError):
                    continue
    else:
        # Parse Linux lsusb output
        for line in device_output.splitlines():
            if "ID " in line:
                try:
                    vendor_id = line.split("ID ")[1].split(":")[0].lower()
                    if vendor_id in MALICIOUS_VENDORS:
                        device_info = " ".join(line.split()[5:])
                        malicious.append(f"{vendor_id}: {device_info}")
                except (IndexError, ValueError):
                    continue
    return malicious

def log_usb_event(device, malicious_list):
    global log_counter
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('usb.log', 'a') as f:
        log_entry = f"[{timestamp}] Devices connected:\n{device}\n"
        if malicious_list:
            log_entry += f"[!] MALICIOUS DEVICES DETECTED:\n"
            log_entry += "\n".join(malicious_list) + "\n"
        log_entry += "-" * 50 + "\n"
        f.write(log_entry)
    log_counter += 1
    if log_counter % 10 == 0 and log_counter > 0:
        from encrypt import encrypt_file
        encrypt_file('usb.log')

@app.route('/')
def home():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices = get_usb_devices()
    malicious_list = detect_malicious(devices)
    log_usb_event(devices, malicious_list)
    return render_template('index.html', devices=devices, malicious=malicious_list, timestamp=timestamp)

# --- ADMIN UNLOCK PAGE ---
@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session.permanent = True
            session['authenticated'] = True
            session['login_time'] = datetime.now().timestamp()
            return render_template('unlock.html', authenticated=True, ports_enabled=ports_enabled, timeout=SESSION_TIMEOUT)
        else:
            return "❌ Incorrect password. Access denied.", 401
    
    authenticated = session.get('authenticated', False)
    if authenticated:
        # Check if session has expired
        login_time = session.get('login_time', 0)
        if datetime.now().timestamp() - login_time > SESSION_TIMEOUT:
            session.clear()
            authenticated = False
            return redirect(url_for('unlock'))
    
    return render_template('unlock.html', authenticated=authenticated, ports_enabled=ports_enabled, timeout=SESSION_TIMEOUT)

@app.route('/check_session')
def check_session():
    authenticated = session.get('authenticated', False)
    if authenticated:
        login_time = session.get('login_time', 0)
        current_time = datetime.now().timestamp()
        time_left = SESSION_TIMEOUT - (current_time - login_time)
        
        if time_left <= 0:
            session.clear()
            return {'authenticated': False, 'time_left': 0}
        
        return {'authenticated': True, 'time_left': int(time_left)}
    return {'authenticated': False, 'time_left': 0}

@app.route('/toggle_ports', methods=['POST'])
def toggle_ports():
    global ports_enabled
    if not session.get('authenticated'):
        return redirect(url_for('unlock'))
    
    action = request.form.get('action')
    if action == 'enable':
        enable_usb_ports()
        ports_enabled = True
    else:
        disable_usb_ports()
        ports_enabled = False
    
    return redirect(url_for('unlock'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/update_devices')
def update_devices():
    devices = get_usb_devices()
    malicious_list = detect_malicious(devices)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        'devices': devices,
        'malicious': malicious_list,
        'timestamp': timestamp,
        'device_count': devices.count('\n') // 4,
        'malicious_count': len(malicious_list)
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
