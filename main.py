from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import subprocess
import re
import logging
from datetime import datetime
import requests

# --- Logger Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- FastAPI App ---
app = FastAPI(title="Network Utility API", version="1.0")

# --- Nmap Path ---
nmap_path = r'D:\nmap\nmap.exe'  # Adjust path if needed

# --- Request Schema for IP Scan ---
class ScanReq(BaseModel):
    ip: str

# --- Nmap IP Scan Function ---
def scan_ip(ip: str):
    logger.info(f"Starting Nmap scan on {ip}")
    cmd = [nmap_path, '-T4', '-A', '-O', '-sV', '-sC', '-p-', '-v', '-Pn', ip]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    port_list = []
    os_info = {}
    dev_type = ''
    svc_info = ''
    script_out = {}
    curr_script = ''
    script_buf = []

    # Regex patterns
    port_re = re.compile(r'^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$')
    os_re = re.compile(r'^OS details: (.*)')
    dev_re = re.compile(r'^Device type: (.*)')
    svc_re = re.compile(r'^Service Info: (.*)')
    script_re = re.compile(r'^\|_(.*):$|^\|\s+(.+?):\s*(.*)')

    for line in iter(proc.stdout.readline, ''):
        line = line.strip()
        if not line:
            continue

        if (m := port_re.match(line)):
            port_list.append({
                'port': int(m.group(1)),
                'service': m.group(2),
                'version': m.group(3) if m.group(3) else None
            })

        elif (m := os_re.match(line)):
            os_info['os'] = m.group(1)

        elif (m := dev_re.match(line)):
            dev_type = m.group(1)

        elif (m := svc_re.match(line)):
            svc_info = m.group(1)

        elif (m := script_re.match(line)):
            if m.group(1):
                if curr_script:
                    script_out[curr_script] = script_buf
                curr_script = m.group(1)
                script_buf = []
            elif m.group(2):
                script_buf.append({m.group(2): m.group(3)})

    if curr_script:
        script_out[curr_script] = script_buf

    proc.stdout.close()
    proc.wait()

    logger.info(f"Scan completed for {ip} with {len(port_list)} open ports.")

    return {
        'ports': port_list,
        'os_info': os_info,
        'device_type': dev_type,
        'service_info': svc_info,
        'script_results': script_out
    }

# --- Geolocation Function ---
def get_geolocation(ip: str = ""):
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

# --- Middleware for Logging All Requests ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    client_ip = request.client.host
    logger.info(f"Incoming request: {request.method} {request.url} from {client_ip}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

# --- Route: IP Scan ---
@app.post("/ip_scan")
async def ip_scan(req: ScanReq):
    logger.info(f"Received scan request for IP: {req.ip}")
    result = scan_ip(req.ip)
    return {
        'target': req.ip,
        'timestamp': datetime.now().isoformat(),
        'scan_data': result
    }

# --- Route: IP Geolocation ---
@app.get("/api/geolocate")
async def geolocate(ip: str = Query(default="", description="IP address to geolocate. Leave blank to auto-detect.")):
    logger.info(f"Geolocation lookup requested for IP: '{ip or 'auto-detect'}'")
    result = get_geolocation(ip)
    return JSONResponse(content=result)

# --- Run the Server ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5010, reload=True)
