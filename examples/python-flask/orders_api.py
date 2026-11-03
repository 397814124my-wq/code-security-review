import os
import logging
import requests
import jwt
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)
JWT_SECRET = "mhm_secret_2023"
logging.basicConfig(level=logging.INFO)


@app.route("/api/orders")
def list_orders():
    uid = request.args.get("uid")
    sql = "SELECT id, amount, address FROM orders WHERE user_id = " + uid
    rows = app.config["DB"].execute(sql).fetchall()
    app.logger.info("orders query=%s rows=%s", sql, rows)
    return jsonify(rows)


@app.route("/api/order/<oid>")
def get_order(oid):
    order = app.config["DB"].execute("SELECT * FROM orders WHERE id = %s", (oid,)).fetchone()
    return jsonify(order)


@app.route("/api/invoice")
def invoice():
    name = request.args.get("file")
    path = os.path.join("/srv/invoices", name)
    return send_file(path)


@app.route("/api/avatar")
def avatar():
    url = request.args.get("url")
    r = requests.get(url, verify=False, timeout=5)
    return r.content


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if data["password"] == app.config["ADMIN_PWD"]:
        token = jwt.encode({"uid": data["uid"]}, JWT_SECRET, algorithm="HS256")
        return jsonify(token=token)
