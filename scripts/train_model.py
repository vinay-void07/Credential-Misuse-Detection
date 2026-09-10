import os
import sys

# Ensure root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.detection.isolation_forest import detector

def main():
    print("[*] Training and persisting IsolationForest baseline anomaly detector...")
    detector._load_or_train_default()
    print(f"[+] Model successfully trained and saved at: {detector.model_path}")

if __name__ == "__main__":
    main()
