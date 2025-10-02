import torch
import torch.nn as nn
from torch.nn.utils import spectral_norm
import joblib
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
import joblib
import numpy as np
import subprocess
import time
from torch.utils.data import Dataset
from cicflowmeter.sniffer import create_sniffer
import threading
from scapy.utils import wrpcap
from core.interfaces import IAnomalyDetector
from torch.utils.data import DataLoader, TensorDataset


class AutoencoderModel(nn.Module):
    def __init__(self):
        super(AutoencoderModel, self).__init__()
        # --- Define encoder ---
        self.encoder = nn.Sequential(
            nn.Linear(76, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(512, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(128, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(32, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(32, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(16, 8)
        )

        # --- Define decoder ---
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.BatchNorm1d(16),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(32, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(32, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(32, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(128, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.1),

            nn.Linear(512, 76)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AEAnomalyDetector(IAnomalyDetector):
    def __init__(self, packets, model_path,
                 error_path,
                 scaler_path,
                 percentile=94,):

        self.packets = packets
        self.model_path = model_path
        self.error_path = error_path
        self.scaler_path = scaler_path
        self.model = AutoencoderModel()
        self.model.load_state_dict(torch.load(model_path, map_location=torch.device("cpu")))
        print("me when")

        # Load error distribution + compute threshold
        all_err = joblib.load(error_path)
        self.all_err=all_err
        self.threshold = np.percentile(all_err, percentile)

        # Load scaler
        self.scaler = joblib.load(scaler_path)

        # How often to run monitor loop (in seconds)
        self.interval = 10

        # Feature list (same as your manual snippet)
        self.features = [
            'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
            'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
            'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max',
            'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
            'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot',
            'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
            'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
            'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
            'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
            'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg',
            'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg',
            'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg',
            'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts',
            'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts',
            'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]

        self.monitor()

    def check(self, x: torch.Tensor):
        """Check anomalies for a given batch or single row."""
        self.model.eval()
        with torch.no_grad():
            output = self.model(x)
            per_sample_loss = torch.mean((output - x) ** 2, dim=1)
            return per_sample_loss.cpu().numpy() > self.threshold

    def monitor(self):
        """Start a sniffer once, and periodically scan the CSV for new flows."""
        sniffer, flow_session = create_sniffer(
            input_interface="\\Device\\NPF_{F38144B9-553E-4B5B-BC8D-135BF82F584F}",
            input_file=None,
            output_mode="csv",
            output="resources/flows.csv"
        )

        sniffer.start()

        def process_loop():
            last_read_rows = 0
            while True:
                try:
                    # Wait a bit for new flows to accumulate
                    time.sleep(self.interval)

                    # Read the CSV
                    df = pd.read_csv("resources/flows.csv")

                    # Only process new rows
                    new_df = df.iloc[last_read_rows:]
                    last_read_rows = len(df)

                    for i, row in new_df[self.features].iterrows():
                        row_np = row.values.reshape(1, -1)
                        scaled = self.scaler.transform(row_np)
                        x = torch.tensor(scaled, dtype=torch.float32)
                        if self.check(x):
                            print(f"Anomaly at flow idx {i}")
                        else:
                            print(f"Normal flow idx {i}")

                except Exception as e:
                    print("[Process loop error]", e)

        proc_thread = threading.Thread(target=process_loop, daemon=True)
        proc_thread.start()

        print("Sniffer running; processing thread started")


        threading.Thread(target=process_loop, daemon=True).start()
        print("Sniffer running; processing thread started")