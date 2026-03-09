"""Intentionally vulnerable test server for StackHawk security scanning.

This server contains deliberate security vulnerabilities for testing purposes.
DO NOT use this code in production.
"""

import sqlite3

from flask import Flask, Response, jsonify, redirect, request
from graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLInputField,
    GraphQLInputObjectType,
    GraphQLInt,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLSchema,
    GraphQLString,
    graphql_sync,
)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
db.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com')")
db.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com')")
db.execute("INSERT INTO users VALUES (3, 'Charlie', 'charlie@example.com')")
db.commit()

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# ---------------------------------------------------------------------------
# OpenAPI spec (served from the app for StackHawk discovery)
# ---------------------------------------------------------------------------

OPENAPI_SPEC = """\
openapi: "3.0.3"
info:
  title: Vulnerable Test API
  version: "1.0.0"
  description: Intentionally vulnerable API for security scanning
servers:
  - url: http://localhost:8080
paths:
  /api/health:
    get:
      summary: Health check
      operationId: healthCheck
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
  /api/users:
    get:
      summary: List or search users
      operationId: listUsers
      parameters:
        - name: search
          in: query
          required: false
          schema:
            type: string
      responses:
        "200":
          description: List of users
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: "#/components/schemas/User"
    post:
      summary: Create a user
      operationId: createUser
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/UserInput"
      responses:
        "200":
          description: User created
          content:
            text/html:
              schema:
                type: string
  /api/users/{user_id}:
    get:
      summary: Get user by ID
      operationId: getUser
      parameters:
        - name: user_id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: User details
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/User"
        "404":
          description: Not found
  /api/search:
    get:
      summary: Search page
      operationId: searchPage
      parameters:
        - name: q
          in: query
          required: false
          schema:
            type: string
      responses:
        "200":
          description: Search results HTML
          content:
            text/html:
              schema:
                type: string
  /api/redirect:
    get:
      summary: Redirect to URL
      operationId: redirectToUrl
      parameters:
        - name: url
          in: query
          required: true
          schema:
            type: string
      responses:
        "302":
          description: Redirect
  /api/file:
    get:
      summary: Read a file
      operationId: readFile
      parameters:
        - name: name
          in: query
          required: true
          schema:
            type: string
      responses:
        "200":
          description: File contents
          content:
            text/plain:
              schema:
                type: string
        "400":
          description: Error
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        email:
          type: string
    UserInput:
      type: object
      required:
        - name
        - email
      properties:
        name:
          type: string
        email:
          type: string
"""


@app.route("/openapi.yaml")
def openapi_spec():
    return Response(OPENAPI_SPEC, content_type="text/yaml")


# ---------------------------------------------------------------------------
# REST endpoints (intentionally vulnerable)
# ---------------------------------------------------------------------------


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/users", methods=["GET"])
def list_users():
    search = request.args.get("search", "")
    # VULN: SQL injection via string formatting
    query = f"SELECT * FROM users WHERE name LIKE '%{search}%'"
    cursor = db.execute(query)
    rows = cursor.fetchall()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id):
    # VULN: SQL injection via unsanitized path parameter
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = db.execute(query)
    row = cursor.fetchone()
    if row:
        return jsonify({"id": row[0], "name": row[1], "email": row[2]})
    return jsonify({"error": "not found"}), 404


@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "")
    email = data.get("email", "")
    # VULN: SQL injection via string formatting
    db.execute(f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')")
    db.commit()
    # VULN: Reflected XSS – user input echoed in HTML without escaping
    return Response(
        f"<html><body>User created: {name}</body></html>",
        content_type="text/html",
    )


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    # VULN: Reflected XSS – query param rendered directly in HTML
    return Response(
        f"<html><body><h1>Search results for: {q}</h1></body></html>",
        content_type="text/html",
    )


@app.route("/api/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # VULN: Open redirect – no validation of target URL
    return redirect(url)


@app.route("/api/file")
def read_file():
    name = request.args.get("name", "")
    # VULN: Path traversal – no sanitisation of file path
    try:
        with open(name) as f:
            content = f.read()
        return Response(content, content_type="text/plain")
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# GraphQL (intentionally vulnerable)
# ---------------------------------------------------------------------------

UserType = GraphQLObjectType(
    "User",
    lambda: {
        "id": GraphQLField(GraphQLInt),
        "name": GraphQLField(GraphQLString),
        "email": GraphQLField(GraphQLString),
    },
)

UserInput = GraphQLInputObjectType(
    "UserInput",
    {
        "name": GraphQLInputField(GraphQLNonNull(GraphQLString)),
        "email": GraphQLInputField(GraphQLNonNull(GraphQLString)),
    },
)


def resolve_users(_obj, _info, search=None):
    if search:
        # VULN: SQL injection
        query = f"SELECT * FROM users WHERE name LIKE '%{search}%'"
    else:
        query = "SELECT * FROM users"
    cursor = db.execute(query)
    return [{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()]


def resolve_user(_obj, _info, id):
    # VULN: SQL injection
    query = f"SELECT * FROM users WHERE id = {id}"
    cursor = db.execute(query)
    row = cursor.fetchone()
    return {"id": row[0], "name": row[1], "email": row[2]} if row else None


def resolve_create_user(_obj, _info, input):
    name = input["name"]
    email = input["email"]
    # VULN: SQL injection
    db.execute(f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')")
    db.commit()
    cursor = db.execute("SELECT last_insert_rowid()")
    new_id = cursor.fetchone()[0]
    return {"id": new_id, "name": name, "email": email}


def resolve_delete_user(_obj, _info, id):
    # VULN: SQL injection
    db.execute(f"DELETE FROM users WHERE id = {id}")
    db.commit()
    return f"User {id} deleted"


schema = GraphQLSchema(
    query=GraphQLObjectType(
        "Query",
        {
            "users": GraphQLField(
                GraphQLList(UserType),
                args={"search": GraphQLArgument(GraphQLString)},
                resolve=resolve_users,
            ),
            "user": GraphQLField(
                UserType,
                args={"id": GraphQLArgument(GraphQLNonNull(GraphQLInt))},
                resolve=resolve_user,
            ),
        },
    ),
    mutation=GraphQLObjectType(
        "Mutation",
        {
            "createUser": GraphQLField(
                UserType,
                args={"input": GraphQLArgument(GraphQLNonNull(UserInput))},
                resolve=resolve_create_user,
            ),
            "deleteUser": GraphQLField(
                GraphQLString,
                args={"id": GraphQLArgument(GraphQLNonNull(GraphQLInt))},
                resolve=resolve_delete_user,
            ),
        },
    ),
)


@app.route("/graphql", methods=["POST"])
def graphql_post():
    data = request.get_json(force=True, silent=True) or {}
    result = graphql_sync(
        schema,
        data.get("query", ""),
        variable_values=data.get("variables"),
        operation_name=data.get("operationName"),
    )
    response = {}
    if result.data is not None:
        response["data"] = result.data
    if result.errors:
        response["errors"] = [
            {
                "message": str(e),
                "locations": [
                    {"line": loc.line, "column": loc.column}
                    for loc in (e.locations or [])
                ],
            }
            for e in result.errors
        ]
    return jsonify(response)


@app.route("/graphql", methods=["GET"])
def graphql_get():
    query_str = request.args.get("query", "")
    if not query_str:
        return jsonify({"error": "query parameter required"}), 400
    result = graphql_sync(schema, query_str)
    response = {}
    if result.data is not None:
        response["data"] = result.data
    if result.errors:
        response["errors"] = [{"message": str(e)} for e in result.errors]
    return jsonify(response)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
