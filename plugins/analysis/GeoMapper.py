# plugins/geomap/MaxMindGeoMapper.py
import geoip2.database
import geoip2.errors
import requests
from typing import Tuple
from core.interfaces import IGeoMapper

class MaxMindGeoMapper(IGeoMapper):
    def __init__(self, geoip_db_path: str, default_lat: float = 30.0444, default_lon: float = 31.2357, default_name: str = "Cairo (Default)"):
        self.geoip_db_path = geoip_db_path
        self.real_location_fetched = False
        self.real_lat = default_lat
        self.real_lon = default_lon
        self.real_location_name = default_name
        self.get_real_location()

    def get_real_location(self):
        """Fetch real location once and store it."""
        try:
            print("[GeoMapper] Detecting real location...")
            response = requests.get('http://ip-api.com/json/', timeout=3).json()
            if response.get('status') == 'success':
                self.real_lat = response.get('lat')
                self.real_lon = response.get('lon')
                city = response.get('city', 'Unknown')
                country = response.get('country', 'Unknown')
                self.real_location_name = f"{city}, {country}"
                print(f"[GeoMapper] Detected real location: {self.real_location_name} ({self.real_lat}, {self.real_lon})")
                self.real_location_fetched = True
                return self.real_lat, self.real_lon, self.real_location_name
            else:
                print("[GeoMapper] IP geolocation failed, using default coordinates")
        except Exception as e:
            print(f"[GeoMapper] Error getting real location: {e}")
            print("[GeoMapper] Using default coordinates")

    def get_location(self, ip: str):
        """Return (lat, lon) for a given IP. Fallback to real location if unknown."""
        try:
            with geoip2.database.Reader(self.geoip_db_path) as reader:
                response = reader.city(ip)
                lat = response.location.latitude
                lon = response.location.longitude
                return lat, lon
        except geoip2.errors.AddressNotFoundError:
            return self.real_lat, self.real_lon
        except Exception as e:
            print(f"[GeoMapper] Error getting location for {ip}: {e}")
            return self.real_lat, self.real_lon
