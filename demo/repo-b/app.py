def find_order(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cur.fetchone()
