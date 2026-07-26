# 🛡️ AI-Powered Behavioral Anomaly Detection

**Honeywell Cybersecurity Hackathon Submission**  
**Team / Author:** druvetron

## Overview
Traditional signature-based security fails against novel, low-and-slow, and credential-compromise intrusions. This repository contains a complete, domain-agnostic **User and Entity Behavior Analytics (UEBA)** system built to solve this. 

Instead of relying on fixed rules, this AI/ML pipeline models the "normal" access and connection behavior for users, service accounts, and edge devices. It flags deviations in near real-time, classifies the specific attack taxonomy, and provides a human-readable explainability score for Security Operations Center (SOC) analysts.

## Key Capabilities
* **Sequence-Aware Detection:** Utilizes a PyTorch GRU Autoencoder to evaluate rolling windows of behavior, catching complex temporal attacks like impossible travel and low-and-slow exfiltration.
* **Multi-Class Threat Taxonomy:** A supervised Random Forest classifies flagged deviations into specific tactics (e.g., Brute Force, Lateral Movement, Credential Stuffing).
* **Explainable AI (XAI):** Integrated SHAP `TreeExplainer` translates mathematical feature importance into plain English sentences (e.g., *"Flagged due to implausible travel/timing velocity"*).
* **Cold-Start & Concept Drift Resilience:** Employs hierarchical role-based fallbacks for new devices and exponential time-decay moving averages for evolving legitimate behavior.
* **SOC Analyst Dashboard:** A fully containerized Streamlit application for real-time alert triage, alert budgeting, and entity timeline investigations.

## Repository Structure

As shown in the root directory, this project is organized as follows:

```text
cyberthreats/
├── behavioral-anomaly-detection/   # 🚀 MAIN PROJECT FOLDER (Source code, config, UI, Docker)
├── access_logs_labeled.csv         # Generated synthetic training data (with ground truth)
├── access_logs_unlabeled.csv       # Raw streaming data for inference testing
└── entity_profiles.csv             # Baseline profiles for cold-start resolution
