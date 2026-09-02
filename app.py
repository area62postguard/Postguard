
import os,re,json,secrets,sqlite3
import psycopg
from psycopg.rows import dict_row
from datetime import datetime
from functools import wraps
from flask import Flask,render_template,request,redirect,url_for,session,jsonify,flash
from werkzeug.security import generate_password_hash,check_password_hash
from PIL import Image,ImageDraw,ImageFilter,ExifTags

BASE=os.path.dirname(os.path.abspath(__file__)); DB=os.path.join(BASE,"data","postguard.db"); UP=os.path.join(BASE,"data","uploads")
os.makedirs(UP,exist_ok=True)
app = Flask(__name__)

app.secret_key = os.getenv(
    "POSTGUARD_SECRET",
    secrets.token_hex(32)
)

app.config.update(
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

class PostgresCompat:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, params=None):
        sql = sql.replace("?", "%s")
        if params is None:
            return self.connection.execute(sql)
        return self.connection.execute(sql, params)

    def executemany(self, sql, params):
        sql = sql.replace("?", "%s")
        cur = self.connection.cursor()
        cur.executemany(sql, params)
        return cur

    def executescript(self, script):
        script = script.replace(
            "id INTEGER PRIMARY KEY",
            "id SERIAL PRIMARY KEY"
        )

        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.connection.execute(statement)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


def db():
    database_url = os.getenv("DATABASE_URL")

    if database_url:
        connection = psycopg.connect(
            database_url,
            row_factory=dict_row
        )
        return PostgresCompat(connection)

    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c
