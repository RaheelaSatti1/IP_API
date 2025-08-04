import subprocess
import json
import re
from datetime import datetime
import requests

def scan_ip(ip):
    nmap_path = r'D:\nmap\nmap.exe'  # Update path if needed
    command = [nmap_path, '-T4', '-A', '-O', '-sV', '-sC', '-p-', '-v', '-Pn', ip]

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    ports = []
    os_info = {}
    device_info = ''
    service_info = ''
    host_script_results = {}
    current_script = ''
    current_script_output = []

    port_pattern = re.compile(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$')
    os_pattern = re.compile(r'^OS details: (.*)')
    device_pattern = re.compile(r'^Device type: (.*)')
    service_info_pattern = re.compile(r'^Service Info: (.*)')
    host_script_pattern = re.compile(r'^\|_(.*):$|^\|\s+(.+?):\s*(.*)')

    for line in iter(process.stdout.readline, ''):
        line = line.strip()
        if not line:
            continue
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {line}")

        port_match = port_pattern.match(line)
        if port_match:
            port_data = {
                'Port': int(port_match.group(1)),
                'Service': port_match.group(2),
                'Version': port_match.group(3) if port_match.group(3) else None
            }
            ports.append(port_data)

        os_match = os_pattern.match(line)
        if os_match:
            os_info['OS Details'] = os_match.group(1)

        device_match = device_pattern.match(line)
        if device_match:
            device_info = device_match.group(1)

        service_match = service_info_pattern.match(line)
        if service_match:
            service_info = service_match.group(1)

        host_script_match = host_script_pattern.match(line)
        if host_script_match:
            if host_script_match.group(1):
                if current_script:
                    host_script_results[current_script] = current_script_output
                current_script = host_script_match.group(1)
                current_script_output = []
            elif host_script_match.group(2):
                key = host_script_match.group(2)
                value = host_script_match.group(3)
                current_script_output.append({key: value})

    if current_script:
        host_script_results[current_script] = current_script_output

    process.stdout.close()
    process.wait()

    return {
        'Ports': ports,
        'OS Information': os_info,
        'Device Type': device_info,
        'Service Info': service_info,
        'Host Script Results': host_script_results
    }

def get_geolocation(ip=""):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        if data['status'] == 'success':
            return {
                "IP": data.get("query"),
                "City": data.get("city"),
                "Region": data.get("regionName"),
                "Country": data.get("country"),
                "Latitude": data.get("lat"),
                "Longitude": data.get("lon"),
                "ISP": data.get("isp"),
                "Org": data.get("org"),
                "Timezone": data.get("timezone"),
            }
        else:
            return {"error": data.get("message", "Failed to retrieve data")}
    except Exception as e:
        return {"error": str(e)}

def main():
    ip_address = input("Enter the IP address or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24): ")

    print("\n[+] Starting Nmap Scan...")
    scan_data = scan_ip(ip_address)

    print("\n[+] Nmap scan completed. Now fetching Geolocation Information...")
    geo_data = get_geolocation(ip_address)

    result = {
        'Target': ip_address,
        'Timestamp': datetime.now().isoformat(),
        'Scan Data': scan_data,
        'Geolocation': geo_data
    }

    json_result = json.dumps(result, indent=4)
    print("\n=== Final JSON Result ===")
    print(json_result)

if __name__ == '__main__':
    main()
