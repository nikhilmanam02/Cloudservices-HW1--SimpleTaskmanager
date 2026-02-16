from flask import Flask, request, redirect, url_for, session, render_template_string
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

app = Flask(__name__)
app.secret_key = "CHANGE_ME_TO_SOMETHING_RANDOM"

# ====== EDIT THESE ======
AD_DOMAIN = "myad.local"                 # your directory DNS name
LDAP_HOST = "172.31.15.37"                 # can also use one of the directory DNS IPs
BASE_DN = "DC=myad,DC=local"             # for myad.local
ADMIN_GROUP_CN = "TaskApp-Admins"
USER_GROUP_CN = "TaskApp-Users"
# ========================

LOGIN_PAGE = """
<h2>AD Task App Login</h2>
<form method="post">
  <label>Username (taskadmin / taskuser):</label><br>
  <input name="username" /><br><br>
  <label>Password:</label><br>
  <input name="password" type="password" /><br><br>
  <button type="submit">Login</button>
</form>
<p style="color:red;">{{error}}</p>
"""

HOME_PAGE = """
<h2>Welcome {{username}}</h2>
<p>Your role: <b>{{role}}</b></p>
<ul>
  <li><a href="/tasks">My Tasks</a></li>
  {% if role == "admin" %}
    <li><a href="/admin">Admin Panel</a></li>
  {% endif %}
  <li><a href="/logout">Logout</a></li>
</ul>
"""

TASKS_PAGE = """
<h2>My Tasks ({{username}})</h2>
<form method="post">
  <input name="task" placeholder="New task" />
  <button type="submit">Add</button>
</form>
<ul>
  {% for t in tasks %}
    <li>{{t}}</li>
  {% endfor %}
</ul>
<p><a href="/">Back</a></p>
"""

ADMIN_PAGE = """
<h2>Admin Panel</h2>
<p>Only AD users in <b>TaskApp-Admins</b> can see this.</p>
<p><a href="/">Back</a></p>
"""

# In-memory tasks (good enough for demo)
USER_TASKS = {}

def ad_auth_and_role(username: str, password: str):
    """
    Authenticate user against AD via LDAP bind and return role ('admin' or 'user').
    """
    # UPN format is simplest: username@domain
    upn = f"{username}@{AD_DOMAIN}"

    server = Server(LDAP_HOST, get_info=ALL)

    # Simple bind (works for Managed Microsoft AD)
    try:
        conn = Connection(server, user=upn, password=password, auto_bind=True)
    except Exception:
        return None, None  # auth failed

    # Find the user's DN and memberOf groups
    search_filter = f"(userPrincipalName={upn})"
    conn.search(search_base=BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["distinguishedName", "memberOf"])

    if not conn.entries:
        conn.unbind()
        return None, None

    entry = conn.entries[0]
    member_of = entry.memberOf.values if "memberOf" in entry else []
    member_of_str = " ".join([str(g) for g in member_of]).lower()

    # Check group membership by CN
    is_admin = f"cn={ADMIN_GROUP_CN.lower()}," in member_of_str
    is_user = f"cn={USER_GROUP_CN.lower()}," in member_of_str

    conn.unbind()

    if is_admin:
        return upn, "admin"
    if is_user:
        return upn, "user"

    # If not in either group, treat as user (or deny)
    return upn, "user"

def require_login():
    return "upn" in session and "role" in session

@app.route("/", methods=["GET"])
def home():
    if not require_login():
        return redirect(url_for("login"))
    return render_template_string(HOME_PAGE, username=session["username"], role=session["role"])

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        upn, role = ad_auth_and_role(username, password)
        if upn:
            session["username"] = username
            session["upn"] = upn
            session["role"] = role
            USER_TASKS.setdefault(username, [])
            return redirect(url_for("home"))
        else:
            error = "Login failed (AD authentication). Check username/password."

    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/tasks", methods=["GET", "POST"])
def tasks():
    if not require_login():
        return redirect(url_for("login"))

    username = session["username"]
    if request.method == "POST":
        task = request.form.get("task", "").strip()
        if task:
            USER_TASKS.setdefault(username, []).append(task)

    return render_template_string(TASKS_PAGE, username=username, tasks=USER_TASKS.get(username, []))

@app.route("/admin")
def admin():
    if not require_login():
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return "Forbidden: Admins only", 403
    return render_template_string(ADMIN_PAGE)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
