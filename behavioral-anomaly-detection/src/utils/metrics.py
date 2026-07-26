import numpy as np
from sklearn.metrics import precision_recall_curve, auc

def evaluate_detection_performance(y_true, y_score, budget_pct=0.01):
    # Calculate PR-AUC
    precision, recall, _ = precision_recall_curve(y_true, y_score)
    pr_auc = auc(recall, precision)
    
    # Calculate Precision at Analyst Budget
    budget_k = max(1, int(len(y_true) * budget_pct))
    
    # Sort by risk score descending
    sorted_indices = np.argsort(y_score)[::-1]
    
    if hasattr(y_true, 'iloc'):
        top_k_labels = y_true.iloc[sorted_indices][:budget_k]
    else:
        top_k_labels = np.array(y_true)[sorted_indices][:budget_k]
        
    precision_at_budget = np.sum(top_k_labels) / budget_k
    
    return {
        'pr_auc': pr_auc,
        f'precision_at_{budget_pct*100}_budget': precision_at_budget
    }