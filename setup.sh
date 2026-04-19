#!/bin/bash
# =============================================
# Phishing Detector - Setup Script
# =============================================

echo "🚀 Setting up Phishing Detector Project..."

# 1. Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# 2. Activate virtual environment
echo "⚡ Activating virtual environment..."
source venv/bin/activate

# 3. Upgrade pip
pip install --upgrade pip

# 4. Install dependencies
echo "📥 Installing dependencies..."
pip install flask flask-mysqldb requests python-dotenv flask-cors

# 5. Save requirements
pip freeze > requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "👉 Next Steps:"
echo "   1. Activate venv:   source venv/bin/activate   (Linux/Mac)"
echo "                       venv\\Scripts\\activate        (Windows)"
echo "   2. Configure .env with your DB and API credentials"
echo "   3. Import database: mysql -u root -p < schema.sql"
echo "   4. Run app:         python app.py"
echo ""
