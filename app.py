from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Users
USERS = {
    "user": {"password": "1234", "role": "user", "id": "1233"},
    "admin": {"password": "1234", "role": "admin", "id": "6755"}
}

# Fake data
USER_DATA = {
    "1233": {
        "name": "John Doe",
        "email": "john@example.com",
        "role": "user",
        "image": "https://i.pravatar.cc/150?img=3"
    },
    "6755": {
        "name": "Admin Boss",
        "email": "admin@example.com",
        "role": "admin",
        "image": "https://i.pravatar.cc/150?img=5"
    }
}

ALL_USERS = [
    {"id": "1233", "name": "John Doe", "role": "user"},
    {"id": "6755", "name": "Admin Boss", "role": "admin"}
]

# Modes
prevention_mode = False
vulnerable_mode = False


# ROOT
@app.route('/')
def home():
    return redirect(url_for('login'))


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']

        if user in USERS and USERS[user]["password"] == pwd:
            session['user'] = user
            session['role'] = USERS[user]["role"]
            session['user_id'] = USERS[user]["id"]

            return redirect(f"/dashboard/user?id={USERS[user]['id']}")

        return "Invalid Credentials ❌"

    return render_template('login.html')


# TOGGLE PREVENTION
@app.route('/toggle')
def toggle():
    global prevention_mode
    prevention_mode = not prevention_mode
    return redirect(f"/dashboard/user?id={session.get('user_id')}")


# TOGGLE VULNERABLE MODE
@app.route('/vuln')
def vuln():
    global vulnerable_mode
    vulnerable_mode = not vulnerable_mode
    return redirect(f"/dashboard/user?id={session.get('user_id')}")


# USER DASHBOARD
@app.route('/dashboard/user')
def user_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    requested_id = request.args.get('id')

    if requested_id != session.get('user_id'):
        msg = "🚨 IDOR Attack Detected!"

        if prevention_mode:
            return "🚫 Access Denied (IDOR Prevented)"
        else:
            return msg

    user = USER_DATA.get(requested_id)

    return render_template(
        "user_dashboard.html",
        user=user,
        uid=requested_id,
        mode=prevention_mode,
        vuln=vulnerable_mode
    )


# ADMIN DASHBOARD
@app.route('/dashboard/admin')
def admin_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    requested_id = request.args.get('id')

    # ⚠️ Vulnerable mode bypass
    if vulnerable_mode:
        user = USER_DATA.get(requested_id)
        return render_template("admin_dashboard.html", user=user, users=ALL_USERS)

    # Role tampering
    url_role = request.args.get('role')
    if url_role and url_role != session.get('role'):
        if prevention_mode:
            return "🚫 Blocked (Role Tampering)"
        else:
            return "🚨 Role Tampering Detected!"

    # Privilege escalation
    if session.get('role') != 'admin':
        if prevention_mode:
            return "🚫 Blocked (Admin Access)"
        else:
            return "🚨 Privilege Escalation Attempt!"

    user = USER_DATA.get(requested_id)
    return render_template("admin_dashboard.html", user=user, users=ALL_USERS)


# DELETE USER
@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    global ALL_USERS

    if session.get('role') != 'admin':
        return "🚫 Access Denied"

    ALL_USERS = [u for u in ALL_USERS if u["id"] != user_id]

    return redirect(f"/dashboard/admin?id={session.get('user_id')}")


# CHANGE ROLE
@app.route('/change_role/<user_id>')
def change_role(user_id):
    if session.get('role') != 'admin':
        return "🚫 Access Denied"

    for u in ALL_USERS:
        if u["id"] == user_id:
            u["role"] = "admin" if u["role"] == "user" else "user"

    return redirect(f"/dashboard/admin?id={session.get('user_id')}")


# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# RUN
if __name__ == '__main__':
    app.run(debug=True)
