from core.interfaces import ITrafficPredictor
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score
from datetime import datetime, timedelta
import numpy as np

class BasicRegressionPredictor(ITrafficPredictor):
    def __init__(self):
        self.model = LinearRegression()
        self.is_trained = False
        self.metrics = {}
        self.predictions = []

    def train(self, packets: list = None, time_series: dict = None) -> None:
        if time_series is None or len(time_series) <= 10:
            print("[Predictor] Not enough data to train.")
            return

        try:
            timestamps = list(time_series.keys())
            base_time = timestamps[0]

            X = np.array([ts - base_time for ts in timestamps]).reshape(-1, 1)
            y = np.array(list(time_series.values()))

            test_size = min(0.2, 10 / len(X))
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)

            self.model.fit(X_train, y_train)
            self.is_trained = True

            if len(X_test) > 0:
                y_pred = self.model.predict(X_test)
                self.metrics["r2"] = r2_score(y_test, y_pred)
        except Exception as e:
            print(f"[Predictor] Error during training: {e}")
            self.is_trained = False

    def predict(self, hours_ahead: float = 0, current_packet_count: int = 0, intervals: list = None) -> list:
        if not self.is_trained:
            print("[Predictor] Model has not been trained.")
            return []

        try:
            base_time = datetime.now().timestamp()

            future_times = []
            future_times.append((datetime.now() + timedelta(hours=hours_ahead)).timestamp())
            future_times_extra = [base_time + 3600 * i for i in intervals]  # already in seconds
            future_times.extend(future_times_extra)
            X_future = np.array([t - base_time for t in future_times]).reshape(-1, 1)

            y_pred = self.model.predict(X_future)
            self.predictions = np.maximum(0, y_pred - current_packet_count)

            return self.predictions.tolist()
        except Exception as e:
            print(f"[Predictor] Error during prediction: {e}")
            return []


    def get_metrics(self) -> dict:
        return self.metrics
