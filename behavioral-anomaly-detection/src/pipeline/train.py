"""
src/pipeline/train.py
Trains the GRU Sequence Detector and the anomaly classifier.
"""
import os
import argparse
import yaml
import pandas as pd
import joblib
from src.features.feature_engineering import engineer_features, get_feature_columns
# 1. Swapped the import to use the SequenceDetector
from src.models.sequence_detector import SequenceDetector
from src.models.anomaly_classifier import AnomalyClassifier
from src.utils.metrics import evaluate_detection_performance

def run_training(config_path: str):
    print(f"[*] Loading training configuration from: {config_path}")
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    data_path = config['paths']['labeled_data']
    model_dir = config['paths']['model_dir']
    os.makedirs(model_dir, exist_ok=True)

    print(f"[*] Loading labeled access logs from {data_path}...")
    df = pd.read_csv(data_path)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='timestamp').reset_index(drop=True)

    print("[*] Engineering sequence and behavioral features...")
    df_feat = engineer_features(df, is_training=True)
    feature_cols = get_feature_columns()

    train_ratio = config.get('training', {}).get('train_ratio', 0.75)
    split_idx = int(len(df_feat) * train_ratio)
    train_df = df_feat.iloc[:split_idx].copy()
    val_df = df_feat.iloc[split_idx:].copy()
    print(f"[+] Data split complete. Train size: {len(train_df)}, Validation size: {len(val_df)}")

    # 2. Train Stage 1: GRU Sequence Detector
    print(f"[*] Initializing Stage 1 PyTorch Sequence Detector (Architecture: {config['sequence_detector']['architecture']})...")
    # Pass the whole config dictionary so it can parse sequence_length, hidden_size, etc.
    profiler = SequenceDetector(config)
    
    # Train only on 'normal' data to learn the baseline sequence patterns
    normal_train = train_df[train_df['label'] == 'normal']
    profiler.fit(normal_train, feature_cols)
    
    # Generate Reconstruction Error scores
    train_df['risk_score'] = profiler.predict_anomaly_score(train_df)
    val_df['risk_score'] = profiler.predict_anomaly_score(val_df)

    # 3. Train Stage 2: Anomaly Classifier
    print(f"[*] Initializing Stage 2 Classifier (Method: {config['anomaly_classifier']['method']})...")
    classifier = AnomalyClassifier()
    classifier.fit(train_df, train_df['label'], feature_cols)

    # 4. Validation Evaluation
    print("\n=== Validation Metrics Summary ===")
    y_true_binary = (val_df['label'] != 'normal').astype(int)
    budget_pct = config['evaluation']['alert_budget_pct']
    
    metrics = evaluate_detection_performance(y_true_binary, val_df['risk_score'], budget_pct=(budget_pct/100.0))
    for metric_name, val in metrics.items():
        print(f" - {metric_name}: {val:.4f}")

    # 5. Model Artifact Persistence
    print(f"\n[*] Exporting trained model artifacts to {model_dir}...")
    # 3. Save outputs. The GRU will save a .pt file and a _meta.pkl file.
    profiler.save(os.path.join(model_dir, "sequence_detector.pt"))
    classifier.save(os.path.join(model_dir, "anomaly_classifier.pkl"))
    print("[+] Architecture training workflow complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default="config/config.yaml", help="Path to config YAML")
    args = parser.parse_args()
    run_training(args.config)