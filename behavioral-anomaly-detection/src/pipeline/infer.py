"""
src/pipeline/infer.py
Inference pipeline for executing continuous evaluation on raw unlabeled data logs.
"""
import os
import argparse
import yaml
import pandas as pd
import joblib
from src.features.feature_engineering import engineer_features, get_feature_columns
from src.models.explainability import AnomalyExplainer
from src.models.sequence_detector import SequenceDetector
from src.models.anomaly_classifier import AnomalyClassifier

def run_inference(config_path: str):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
        
    input_path = config['paths']['raw_data']
    output_path = "data/scored_alerts.csv"  # standard drop folder for the dashboard
    model_dir = config['paths']['model_dir']

    print(f"[*] Initializing Inference Engine. Loading models from: {model_dir}")
    
    # 1. Load the PyTorch GRU Sequence Detector
    detector_path = os.path.join(model_dir, "sequence_detector.pt")
    profiler = SequenceDetector.load(config, detector_path)
    
    # 2. Load the Anomaly Classifier
    classifier_data = joblib.load(os.path.join(model_dir, "anomaly_classifier.pkl"))
    classifier = AnomalyClassifier()
    classifier.classifier = classifier_data['model']
    classifier.label_encoder = classifier_data['le']
    classifier.features = classifier_data['features']

    print(f"[*] Processing incoming telemetry file: {input_path}")
    raw_df = pd.read_csv(input_path)
    
    for col in ['label', 'attack_group_id', 'is_edge_case']:
        if col in raw_df.columns:
            raw_df = raw_df.drop(columns=[col])

    processed_df = engineer_features(raw_df, is_training=False)
    feature_cols = get_feature_columns()

    print("[*] Scoring sequences & generating attributions...")
    processed_df['risk_score'] = profiler.predict_anomaly_score(processed_df)
    
    # Normalize risk scores linearly between 0 and 10 for analyst readability
    min_s, max_s = processed_df['risk_score'].min(), processed_df['risk_score'].max()
    if max_s - min_s > 0:
        processed_df['risk_score'] = 10 * (processed_df['risk_score'] - min_s) / (max_s - min_s)
    else:
        processed_df['risk_score'] = 0.0

    # Classify anomalies
    processed_df['predicted_anomaly'] = classifier.predict(processed_df)
    
    # Override classification if risk is below the alert threshold (e.g., 6.5)
    alert_thresh = config.get('model', {}).get('alert_threshold', 6.5)
    processed_df.loc[processed_df['risk_score'] < alert_thresh, 'predicted_anomaly'] = 'Normal'

    # Explainability
    explainer = AnomalyExplainer(classifier.classifier)
    explanations = []
    for idx, row in processed_df.iterrows():
        if row['predicted_anomaly'] != 'Normal':
            row_df = pd.DataFrame([row[feature_cols]])
            explanations.append(explainer.explain_instance(row_df, feature_cols))
        else:
            explanations.append("Behavior exhibits baseline characteristics.")
    processed_df['explanation'] = explanations

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    processed_df.to_csv(output_path, index=False)
    print(f"[+] Scored alerts successfully written to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default="config/config.yaml")
    args = parser.parse_args()
    run_inference(args.config)