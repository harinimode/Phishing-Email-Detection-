Phishing Email Detection (ML + URL Analysis)
📌 Overview
This project detects phishing emails using a machine learning model trained on email text data, combined with real-time URL scanning via the VirusTotal API.
It provides a multi-layer defense:

ML-based detection for suspicious language patterns.

URL-based detection for malicious or suspicious links.

🗂 Project Structure
bash
Copy
Edit
PHISHING/
│
├── Phishing_Email.csv        # Dataset (email text + labels)
├── train_model.py            # Train the ML model and save it
├── testing_model.py          # Test the trained model on new samples
├── new_finalll.py            # Final script combining ML + VirusTotal API
└── model/                    # Folder containing saved .pkl model files
⚙️ Features
Machine Learning Model (Logistic Regression + TF-IDF)

Suspicious URL Detection using:

Keyword heuristics

VirusTotal API lookup

Interactive CLI to test emails in real-time

High Accuracy (~97% on sample dataset)

📊 Dataset
The dataset (Phishing_Email.csv) contains:

Email Text → Email body/content

Label → Phishing or Safe

This dataset is from Kaggle and has been preprocessed for training.

🚀 Installation & Setup
1️⃣ Clone the Repository

git clone https://github.com/yourusername/phishing-email-detector.git

cd phishing-email-detector

2️⃣ Install Dependencies

pip install -r requirements.txt
requirements.txt



scikit-learn
pandas
joblib
requests
python-dotenv
3️⃣ Add VirusTotal API Key
Create a .env file in the project folder:


VIRUSTOTAL_API_KEY=your_api_key_here
(If you don’t have an API key, get one from https://www.virustotal.com/gui/join-us)

🛠 Usage
Train the Model

python train_model.py
Test the Model

python testing_model.py
Run the Final Detection Tool


python new_finalll.py
Paste an email’s text into the terminal, and it will:

Predict Phishing or Safe using ML.

Extract URLs from the email.

Check them via VirusTotal API.

Return results + list of found URLs.

📈 Sample Output
markdown


📧 Prediction: Phishing (Suspicious URL Detected)
🔗 URLs Found:
   - http://fakebank-login.com
----------------------------------------
🧠 Model Details
Vectorization: TF-IDF

Classifier: Logistic Regression

Evaluation Metrics:

Accuracy: ~97%

F1 Score: ~97%

ROC AUC: ~0.98

📌 Future Improvements
Add GUI (Streamlit/Tkinter) for easier use.

Batch process multiple emails at once.

Store results in a database for tracking.

