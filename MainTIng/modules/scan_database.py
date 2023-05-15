import sqlite3

def scan_database(target):
    vulnerabilities = []
    conn = sqlite3.connect(target)
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table"')
    tables = cursor.fetchall()
    for table in tables:
        cursor.execute(f'SELECT * FROM {table}')
        rows = cursor.fetchall()
        for row in rows:
            for column in row:
                if '<script>' in str(column):
                    vulnerabilities.append({'table': table, 'column': column, 'type': 'XSS'})
                if 'DROP TABLE' in str(column):
                    vulnerabilities.append({'table': table, 'column': column, 'type': 'SQL injection'})
    return vulnerabilities