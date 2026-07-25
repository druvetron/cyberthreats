"""
metrics.py — evaluation utilities suited to extreme class imbalance.

Plain accuracy is meaningless here (>97% of rows are "normal" — a model
that predicts "normal" for everything scores >97% accuracy and is useless).
Use instead:

    pr_auc(y_true, scores)
        Precision-Recall AUC — the right ranking metric under heavy
        imbalance (unlike ROC-AUC, which is optimistic when negatives
        vastly outnumber positives).

    precision_at_alert_budget(y_true, scores, budget_pct=1.0)
        "If a SOC analyst can only review the top 1% of scored events
        today, what fraction of those are real anomalies?" — the metric
        that actually reflects operational usefulness.

    recall_at_alert_budget(y_true, scores, budget_pct=1.0)
        Of all true anomalies, what fraction fall inside that top-1% cut?

    per_class_f1(y_true_type, y_pred_type)
        F1 per anomaly_type from anomaly_classifier, so a rare class
        (e.g. device_spoofing) doesn't get hidden inside an averaged score.

    false_positive_rate_on_edge_cases(y_pred, edge_case_mask)
        Specifically checks how often insider_drift_edge_case rows get
        flagged as a hard anomaly — the concept-drift / FP-tuning metric
        called out in the evaluation criteria.

TODO — implement using sklearn.metrics as the base (average_precision_score,
precision_recall_curve, f1_score) plus the two alert-budget helpers above,
which sklearn doesn't provide directly.
"""
