# AI-Powered Phishing Email Detector

A production-ready, highly aesthetic cybersecurity application that classifies emails into **Safe**, **Suspicious**, or **Phishing** using a hybrid approach of Machine Learning (TF-IDF + Logistic Regression) and Heuristic Indicator analysis. It features a modern, glassmorphic dark-theme dashboard, a detailed threat analyzer with a **Risk Heatmap** and **Explainable AI (XAI)** visualizations, PDF reporting, and a fully functional **Browser Extension**.

---

## 🛡️ Key Features

1. **Security Operations Dashboard**: Real-time telemetry showing total scans, threat level breakdowns, average confidence, risk score distributions, and recent scan logs.
2. **Deep Threat Analyzer**: 
   - Paste raw email text or drag-and-drop `.txt`/`.eml` files.
   - **Risk Heatmap**: Highlights dangerous phishing keywords in glowing red.
   - **Explainable AI (XAI)**: Displays a horizontal bar chart showing the exact words that contributed most to the AI's decision.
   - **PDF Report Export**: Download a clean, formatted PDF security audit of the scan results.
3. **Heuristic Indicator Profiling**: Scans for 10 critical threat vectors:
   - Urgent Language, Credential Harvesting, Password Requests, Banking Fraud, Financial Scams, Cryptocurrency Scams, Suspicious URLs, Spoofed Senders, Grammar/Tone Issues, and Dangerous Attachments.
4. **QR Code Phishing Scan (Bonus)**: Automatically extracts and decodes QR codes from email attachments (images), checks the extracted URLs against reputation heuristics, and factors them into the risk score.
5. **Browser Extension (Bonus)**: A Manifest V3 Chrome/Edge extension that adds a right-click context menu option ("Scan for Phishing") to analyze highlighted text instantly.
6. **Robust Security**:
   - Parameterized SQLite queries via SQLAlchemy ORM to prevent SQL Injection.
   - Input sanitization (stripping dangerous scripts/elements) to prevent Cross-Site Scripting (XSS).
   - Strict file upload validation (supports only `.txt`/`.eml`, max 5MB).

---

## 🛠️ Tech Stack

- **Frontend**: React.js, TypeScript, Tailwind CSS, Framer Motion, Axios, Recharts, Lucide React, Canvas-Confetti, jsPDF.
- **Backend**: Python 3.11, FastAPI, Uvicorn, SQLAlchemy (SQLite), Pillow, Pyzbar (QR scanning).
- **Machine Learning**: Scikit-learn, Pandas, NumPy, NLTK, Joblib.
- **Deployment**: Docker, Docker Compose.

---

## 📁 Project Structure

```
├── backend/
│   ├── app/
│   │   ├── classifier.py      # ML classification & XAI feature weights
│   │   ├── database.py        # SQLite connection setup
│   │   ├── indicators.py      # Heuristic threat vector checks
│   │   ├── main.py            # FastAPI endpoints & security controls
│   │   ├── models.py          # SQLAlchemy history schema
│   │   ├── schemas.py         # Pydantic request/response models
│   │   └── utils.py           # EML/TXT parsing, QR scanning, sanitization
│   ├── dataset/
│   │   ├── generate_dataset.py# Synthetic dataset generator
│   │   └── emails.csv          # Generated training dataset
│   ├── models/
│   │   ├── train.py           # Preprocessing & model training script
│   │   ├── model.pkl          # Trained Logistic Regression model (Gitignored)
│   │   └── vectorizer.pkl     # Trained TF-IDF vectorizer (Gitignored)
│   └── requirements.txt       # Backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/        # Dashboard, Analyzer, History, ExtensionInfo
│   │   ├── App.tsx            # Main React controller & sidebar layout
│   │   ├── index.css          # Tailwind & custom glassmorphism styles
│   │   └── main.tsx
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── static/
│   └── extension/             # Manifest V3 browser extension
│       ├── manifest.json
│       ├── background.js
│       ├── popup.html
│       ├── popup.css
│       ├── popup.js
│       └── icon.png
├── Dockerfile                 # Multi-stage production build
├── docker-compose.yml         # Local orchestration
└── README.md                  # Documentation
```

---

## 🚀 Installation & Setup

### Prerequisites
- **Python 3.11** (recommended for pre-compiled wheels)
- **Node.js 18+** & **npm**
- **zbar** shared library (optional, required only for QR code decoding):
  - *Windows*: Automatically included if `pyzbar` wheel installs, or install zbar binaries.
  - *Ubuntu/Debian*: `sudo apt-get install libzbar0`
  - *macOS*: `brew install zbar`

---

### 1. Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Generate the training dataset:
   ```bash
   python dataset/generate_dataset.py
   ```
4. Train the ML model:
   ```bash
   python models/train.py
   ```
5. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   The API will be available at `https://finalcheck-1.onrender.com`. You can view the interactive Swagger documentation at `https://finalcheck-1.onrender.com/docs`.

---

### 2. Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```
2. Install the npm packages:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   The web application will be available at `http://localhost:5173`.

---

## 🐳 Docker Deployment

To run the entire application in a single production-ready container (where FastAPI serves both the API and the compiled React static files):

1. From the project root, run:
   ```bash
   docker-compose up --build
   ```
2. Open your browser and navigate to `http://localhost:8000`.

---



---

## 📡 API Reference

### 1. Scan Text Content
- **Endpoint**: `POST /api/predict`
- **Request Body**:
  ```json
  {
    "text": "Dear customer, your bank account is suspended. Verify immediately: http://chase-bank-verify.com"
  }
  ```
- **Response**: Returns threat classification, confidence, risk score, triggered indicators, XAI keywords, and HTML-highlighted text.

### 2. Scan EML or TXT File
- **Endpoint**: `POST /api/upload`
- **Content-Type**: `multipart/form-data`
- **Payload**: `file` (binary, max 5MB, `.txt` or `.eml`)
- **Response**: Same structure as `/api/predict`. If it's an `.eml` file, it parses headers, sender, and scans image attachments for QR code phishing.

### 3. Get Scan History
- **Endpoint**: `GET /api/history`
- **Query Params**: `limit` (default 50), `skip` (default 0)
- **Response**: List of past scan results.

### 4. Get Dashboard Statistics
- **Endpoint**: `GET /api/stats`
- **Response**: Total scans, breakdown by class, average confidence, risk score distribution, and top 5 recent scans.

---

## 🧠 Explainable AI (XAI) Details

To make the classification transparent, our model uses **local feature importance mapping**:
1. When an email is scanned, it is preprocessed and vectorized using the TF-IDF model.
2. We extract the mathematical coefficients (`model.coef_`) from the trained Logistic Regression model.
3. For every word present in the email, we multiply its TF-IDF score by its coefficient for the "Phishing" or "Safe" class.
4. The words with the highest positive weights are classified as **Danger Keywords** (pushing the score towards Phishing), while negative or safe-associated words are classified as **Safe Keywords**.
5. These weights are plotted in a horizontal bar chart on the UI, and the high-risk words are highlighted in red in the email body.
#   e f i n a l  
 