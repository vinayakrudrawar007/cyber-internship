from flask import Flask, request, render_template_string

app = Flask(__name__)

SQL_INJECTION_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert(1)</script>"

HTML_FORM = """
<!doctype html>
<title>Vulnerable Test Form</title>
<h2>Test Form</h2>
<form method="POST" action="/submit">
  <label>Username: <input type="text" name="username"></label><br><br>
  <label>Password: <input type="password" name="password"></label><br><br>
  <input type="submit" value="Login">
</form>
{% if user_input %}
<p>You submitted: {{ user_input }}</p>
{% endif %}
"""

@app.route("/")
def index():
    return HTML_FORM

@app.route("/submit", methods=["POST"])
def submit():
    username = request.form.get("username","")
    password = request.form.get("password","")
    # Reflected XSS vulnerable display
    user_input = username
    # Simulated SQL injection logic (just printing request)
    if password == SQL_INJECTION_PAYLOAD:
        # Indicate SQL injection detected
        user_input += " (SQL injection payload detected!)"
    return render_template_string(HTML_FORM, user_input=user_input)

if __name__ == "__main__":
    app.run(port=8000)
