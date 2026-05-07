import pytest
from plugins.analysis.GeoMapper import MaxMindGeoMapper


# ─────────────────────────────
# FIXTURES
# ─────────────────────────────

@pytest.fixture
def mapper():
    """
    Fully isolated mapper with injected dependencies
    """

    class FakeHTTP:
        def get(self, *args, **kwargs):
            class Resp:
                def json(self):
                    return {
                        "status": "success",
                        "lat": 10.0,
                        "lon": 20.0,
                        "city": "TestCity",
                        "country": "TestCountry"
                    }
            return Resp()

    class FakeReader:
        class location:
            latitude = 55.5
            longitude = 66.6

        def city(self, ip):
            class Resp:
                location = FakeReader.location()
            return Resp()

    def fake_reader_factory():
        return FakeReader()

    return MaxMindGeoMapper(
        geoip_reader_factory=fake_reader_factory,
        http_client=FakeHTTP()
    )


# ─────────────────────────────
# get_real_location tests
# ─────────────────────────────

def test_get_real_location_success(mapper):
    lat, lon, name = mapper.get_real_location()

    assert lat == 10.0
    assert lon == 20.0
    assert name == "TestCity, TestCountry"
    assert mapper.real_location_fetched is True


def test_get_real_location_failure_fallback():
    class FailHTTP:
        def get(self, *args, **kwargs):
            raise Exception("network down")

    def dummy_reader_factory():
        raise Exception("should not be used")

    mapper = MaxMindGeoMapper(
        geoip_reader_factory=dummy_reader_factory,
        http_client=FailHTTP()
    )

    lat, lon, name = mapper.get_real_location()

    assert lat == 30.0444
    assert lon == 31.2357
    assert name == "Cairo (Default)"


# ─────────────────────────────
# get_location success
# ─────────────────────────────

def test_get_location_success():
    class FakeResponse:
        class location:
            latitude = 55.5
            longitude = 66.6

    class FakeReader:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def city(self, ip):
            return FakeResponse()

    def fake_factory():
        return FakeReader()

    mapper = MaxMindGeoMapper(
        geoip_reader_factory=fake_factory,
        http_client=object()
    )

    lat, lon = mapper.get_location("8.8.8.8")

    assert lat == 55.5
    assert lon == 66.6


# ─────────────────────────────
# get_location IP not found
# ─────────────────────────────

def test_get_location_ip_not_found(mapper):
    import geoip2.errors

    class FailReader:
        def city(self, ip):
            raise geoip2.errors.AddressNotFoundError()

    def factory():
        return FailReader()

    mapper.geoip_reader_factory = factory

    lat, lon = mapper.get_location("1.2.3.4")

    assert lat == mapper.real_lat
    assert lon == mapper.real_lon


# ─────────────────────────────
# get_location generic failure
# ─────────────────────────────

def test_get_location_generic_error(mapper):
    class FailReader:
        def city(self, ip):
            raise Exception("DB crash")

    mapper.geoip_reader_factory = lambda: FailReader()

    lat, lon = mapper.get_location("1.2.3.4")

    assert lat == mapper.real_lat
    assert lon == mapper.real_lon