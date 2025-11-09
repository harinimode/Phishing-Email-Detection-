import joblib

# Step 1: Load the saved model
model = joblib.load("model/phishing_model.pkl")

# Step 2: Load the saved label binarizer
label_binarizer = joblib.load("model/label_binarizer.pkl")

# Step 3: Define new email(s) to test
# Step 3: Define new email(s) to test
new_emails = [
    """Microsoft account Your password changed Your password for the Microsoft account ethan@hooksecurity.co was changed. 
    If this was you, then you can safely ignore this email. Security info used:
    Country/region: United States 
    Platform: IOS 
    Browser: Safari 
    IP address: 77.196.86.10 
    If this wasn't you, your account has been compromised. Please follow these steps:
    1. Reset your password.
    2. Review your security info.
    3. Learn how to make your account more secure.
    You can also opt out or change where you receive security notifications.
    Thanks,
    The Microsoft account team""",

    "Hey John, just wanted to check in about the meeting schedule for next week."
]


# Step 4: Make predictions
predictions = model.predict(new_emails)

# Step 5: Convert encoded labels back to readable format
readable_predictions = label_binarizer.inverse_transform(predictions)

# Step 6: Print results
for email, result in zip(new_emails, readable_predictions):
    print(f"\nEmail:\n{email}\nPredicted Label: {result}")
