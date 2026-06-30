AI Phishing Email Detector
Overview

Phishing emails are one of the most common cyber threats today. They are designed to trick users into revealing sensitive information such as passwords, bank details, or personal data.

This project uses Machine Learning to analyze email content and predict whether an email is Phishing or Legitimate. The goal is to provide a simple, fast, and easy-to-use tool that helps users identify suspicious emails.

Features
Detects phishing emails using Machine Learning
User-friendly web interface
Instant prediction results
Simple and responsive design
Easy to deploy locally
Technologies Used
Python
Flask
Scikit-learn
Pandas
NumPy
HTML
CSS
Project Structure
AI-Phishing-Detector/
│
├── app.py
├── model.pkl
├── vectorizer.pkl
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── images/
├── dataset/
│   └── phishing_email.csv
└── README.md
Installation

Clone the repository

git clone https://github.com/yourusername/AI-Phishing-Detector.git

Move into the project directory

cd AI-Phishing-Detector

Install the required packages

pip install -r requirements.txt

Run the application

python app.py

Open your browser and visit

http://127.0.0.1:5000
How It Works
The user enters the email text.
The email is converted into numerical features using a trained vectorizer.
The Machine Learning model analyzes the content.
The application predicts whether the email is phishing or legitimate.
The result is displayed instantly.
Future Improvements
URL reputation checking
Attachment analysis
Email header inspection
AI explanation for predictions
Browser extension
Multi-language support
Screenshots
Home Page
(Add screenshot here)
Detection Result
(Add screenshot here)
Learning Outcomes

While building this project, I learned:

Text preprocessing
Feature extraction using TF-IDF
Training Machine Learning models
Building web applications with Flask
Integrating ML models into web applications
Basic deployment workflow
Author

Harshan Seliyan B.S.

Information Technology Student | Cybersecurity & AI Enthusiast
