import sqlite3

def init_db():
    conn = sqlite3.connect("health_platform.db")
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Create health data table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS health_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            height REAL,
            weight REAL,
            bmi REAL,
            health_score REAL,
            checkup_advice TEXT,
            exercise_duration TEXT,
            exercise_type TEXT,
            exercise_frequency TEXT,
            protein_intake TEXT,
            carb_intake TEXT,
            fat_intake TEXT,
            sleep_duration TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

# Initialize the database
if __name__ == "__main__":
    init_db()
