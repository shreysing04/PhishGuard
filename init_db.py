import pymysql
import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def init_db():
    print("Connecting to MySQL...")
    host = os.getenv('MYSQL_HOST', 'localhost')
    user = os.getenv('MYSQL_USER', 'root')
    password = os.getenv('MYSQL_PASSWORD', '')
    
    try:
        # Connect to MySQL (without a specific database)
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            autocommit=True
        )
        cur = conn.cursor()
        
        print(f"Reading schema.sql...")
        with open('schema.sql', 'r') as f:
            sql = f.read()
            
        # Remove comments and split by semicolon
        # This is a simple parser that handles most basic SQL scripts
        sql = re.sub(r'--.*', '', sql)
        statements = sql.split(';')
        
        print("Executing SQL statements...")
        for statement in statements:
            stmt = statement.strip()
            if stmt:
                try:
                    cur.execute(stmt)
                except Exception as e:
                    # Ignore "database already exists" or similar if needed, 
                    # but here we'll just print and continue
                    print(f"Executing: {stmt[:50]}...")
                    print(f"Result: {e}")
        
        cur.close()
        conn.close()
        print("\n[SUCCESS] Database initialized successfully!")
        
    except Exception as e:
        print(f"\n[ERROR] Failed to connect to MySQL: {e}")
        print("\nPlease ensure:")
        print("1. MySQL server is running.")
        print(f"2. User '{user}' has correct permissions.")
        print(f"3. Password is correct in .env file.")
        exit(1)

if __name__ == "__main__":
    init_db()
