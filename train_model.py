import pandas as pd
import matplotlib.pyplot as plt
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, f1_score, roc_auc_score, roc_curve, auc
from sklearn.preprocessing import LabelBinarizer

# Load the dataset
df = pd.read_csv(r'C:\Users\HARSHITHA\Downloads\Python\PHISHING\Phishing_Email.csv\Phishing_Email.csv')
df = df.dropna(subset=['Email Text', 'Email Type'])
df.reset_index(drop=True, inplace=True)

# Features and labels
X = df['Email Text']
y = df['Email Type']

# Label encoding
lb = LabelBinarizer()
y_encoded = lb.fit_transform(y)

# For binary case, flatten labels
if y_encoded.shape[1] == 1:
    y_encoded = y_encoded.flatten()

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# Pipeline: TF-IDF + Logistic Regression
model = Pipeline([
    ('tfidf', TfidfVectorizer(stop_words='english')),
    ('clf', LogisticRegression(solver='liblinear'))
])

# Train the model
model.fit(X_train, y_train)

# Predictions and probabilities
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, y_pred))
print("F1 Score:", f1_score(y_test, y_pred, average='weighted'))
print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=lb.classes_))

# ROC Curve Plotting
plt.figure(figsize=(8, 6))
if len(lb.classes_) == 2:
    fpr, tpr, _ = roc_curve(y_test, y_proba[:, 1])
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, color='blue', label=f'ROC Curve (AUC = {roc_auc:.2f})')
else:
    for i in range(len(lb.classes_)):
        fpr, tpr, _ = roc_curve(y_test[:, i], y_proba[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, label=f'{lb.classes_[i]} (AUC = {roc_auc:.2f})')

plt.plot([0, 1], [0, 1], color='gray', linestyle='--')
plt.title("ROC Curve")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# Save the trained model
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/phishing_model.pkl")
print("✅ Model saved to model/phishing_model.pkl")

# Save label binarizer too (for decoding predictions later)
joblib.dump(lb, "model/label_binarizer.pkl")
print("✅ Label Binarizer saved to model/label_binarizer.pkl")
