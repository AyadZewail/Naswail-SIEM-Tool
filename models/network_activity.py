class NetworkActivity:
    def __init__(self, activity: str = "", mac_of_device: str = ""):
        self.activity = activity
        self.mac_of_device = mac_of_device

    def __repr__(self):
        return f"NetworkActivity(activity={self.activity}, mac_of_device={self.mac_of_device})"

    def __str__(self):
        return f"{self.activity} | MAC: {self.mac_of_device}"