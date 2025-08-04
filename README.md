# IP_API

This project combines two powerful APIs into a single FastAPI service:

- **IP Scanner API**: Performs an advanced Nmap scan on a given IP address.
- **Geolocation API**: Retrieves geographical and ISP information for any public IP using ip-api.com.

### Endpoints

- `POST /ip_scan`  
  🔍 Input: `{ "ip": "8.8.8.8" }`  
  🧪 Output: Detailed scan data (open ports, OS info, services, scripts)

- `GET /api/geolocate?ip=8.8.8.8`  
  📍 Output: Geolocation info (country, region, ISP, coordinates, etc.)

### Setup

```bash
pip install -r requirements.txt
uvicorn main:app --reload
