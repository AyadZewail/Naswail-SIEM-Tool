import geoip2.errors
from typing import Callable, Any, Tuple


class MaxMindGeoMapper:
    def __init__(
        self,
        geoip_reader_factory: Callable[[], Any],
        http_client: Any,
        default_lat: float = 30.0444,
        default_lon: float = 31.2357,
        default_name: str = "Cairo (Default)"
    ):
        self.geoip_reader_factory = geoip_reader_factory
        self.http_client = http_client

        self.real_lat = default_lat
        self.real_lon = default_lon
        self.real_location_name = default_name
        self.real_location_fetched = False

    # -------------------------
    # Real location (external HTTP injected)
    # -------------------------
    def get_real_location(self):
        try:
            response = self.http_client.get(
                "http://ip-api.com/json/",
                timeout=3
            ).json()

            if response.get("status") == "success":
                self.real_lat = response.get("lat", self.real_lat)
                self.real_lon = response.get("lon", self.real_lon)

                city = response.get("city", "Unknown")
                country = response.get("country", "Unknown")

                self.real_location_name = f"{city}, {country}"
                self.real_location_fetched = True

                return self.real_lat, self.real_lon, self.real_location_name

        except Exception:
            # fail silently, fallback remains default
            pass

        return self.real_lat, self.real_lon, self.real_location_name

    # -------------------------
    # GeoIP lookup (DB injected)
    # -------------------------
    def get_location(self, ip: str) -> Tuple[float, float]:
        try:
            with self.geoip_reader_factory() as reader:
                response = reader.city(ip)
                return (
                    response.location.latitude,
                    response.location.longitude
                )

        except geoip2.errors.AddressNotFoundError:
            return self.real_lat, self.real_lon

        except Exception:
            return self.real_lat, self.real_lon