import sqlite3
import subprocess

DB_PASSWORD = "hunter2-prod"


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cur.fetchone()


def ping(host):
    return subprocess.run("ping -c 1 " + host, shell=True)
