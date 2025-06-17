# 🔐 NS-PROJECT: Encrypted USB Logger

A USB monitoring and security tool built with **Python (Flask)** and **HTML/CSS**. It detects USB device insertions/removals, logs activity, identifies suspicious Vendor IDs, disables/enables USB ports, and encrypts logs using GPG.

## 🚀 Features

- 🔍 **Real-Time USB Monitoring**
- ⚠️ **Malicious Vendor ID Detection**
- 🔐 **GPG Encryption for Logs**
- 📁 **Detailed Log Storage**
- ⛔ **Disable/Enable USB Ports**
- 🌐 **Flask-based Web Interface**

---

## 📁 Project Structure

NS-PROJECT/
├── app/
│ ├── templates/
│ │ └── index.html
│ ├── static/
│ │ └── style.css
│ ├── usb_logger.py
│ ├── detector.py
│ ├── gpg_encryptor.py
│ └── utils.py
├── logs/
│ └── (encrypted logs stored here)
├── requirements.txt
├── README.md
└── run.py

---

## ⚙️ Installation

1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/NS-PROJECT.git
cd NS-PROJECT
Create Virtual Environment (Optional but Recommended)

bash
Copy
Edit
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install Dependencies

bash
Copy
Edit
pip install -r requirements.txt
Install GPG (If not installed)
Download and install Gpg4win for Windows.

🔐 GPG Setup
Generate a GPG key (or use an existing one):

bash
Copy
Edit
gpg --full-generate-key
Get your GPG key ID:

bash
Copy
Edit
gpg --list-keys
Update your gpg_encryptor.py with your key ID.

▶️ Usage
Run the App

bash
Copy
Edit
python run.py
Open in browser:

cpp
Copy
Edit
http://127.0.0.1:5000/
Connect or remove USB devices to test logging and detection.

🛡️ Security Features
GPG encrypts logs periodically

Flags USBs with known suspicious Vendor IDs

Optionally disables USB ports for added security

📦 Future Improvements
GUI for decryption and log viewing

Integration with antivirus scanners (e.g. ClamAV)

Real-time alert system for detected threats

🤝 Contribution
Pull requests are welcome! For major changes, open an issue first to discuss what you’d like to change.

📄 License
This project is licensed under the MIT License. See LICENSE for details.

👩‍💻 Developed By
Raiya B
Cybersecurity Student | Air University Islamabad
