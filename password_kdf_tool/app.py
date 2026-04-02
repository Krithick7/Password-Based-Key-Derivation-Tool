from flask import Flask, render_template_string, request

from password_kdf_module import PasswordKDFError, generate_password_report

app = Flask(__name__)

HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Password KDF Local Tester</title>
  <style>
    body { font-family: Segoe UI, sans-serif; margin: 2rem; background: #f7f7fb; color: #222; }
    .card { background: #fff; max-width: 760px; padding: 1.2rem 1.4rem; border-radius: 10px; box-shadow: 0 1px 8px rgba(0,0,0,0.08); }
    input[type=password] { width: 100%; padding: 0.65rem; margin: 0.5rem 0 0.8rem; }
    button { padding: 0.6rem 1rem; border: 0; border-radius: 6px; background: #2f6fed; color: #fff; cursor: pointer; }
    .error { color: #b00020; margin-top: 0.8rem; }
    pre { background: #111; color: #e6e6e6; padding: 1rem; border-radius: 8px; overflow-x: auto; }
    .hint { font-size: 0.92rem; color: #555; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Password KDF Local Tester</h2>
    <p class="hint"></p>
    <form method="post">
      <label for="password">Enter password</label>
      <input id="password" name="password" type="password" required />
      <button type="submit">Analyze</button>
    </form>

    {% if error %}
      <div class="error">{{ error }}</div>
    {% endif %}

    {% if report %}
      <h3>Results</h3>
      <pre>
PBKDF2 key length: {{ report["pbkdf2_key_length"] }}
PBKDF2 verify: {{ report["pbkdf2_verify"] }}
bcrypt hash: {{ report["bcrypt_hash"] }}
bcrypt verify: {{ report["bcrypt_verify"] }}
scrypt key length: {{ report["scrypt_key_length"] }}
scrypt verify: {{ report["scrypt_verify"] }}
Strength score: {{ report["strength_score"] }}
Strength rating: {{ report["strength_rating"] }}
Entropy bits: {{ report["entropy_bits"] }}
Recommendations: {{ report["recommendations"] }}
      </pre>
    {% endif %}
  </div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def home():
    report = None
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        try:
            report = generate_password_report(password)
        except PasswordKDFError as exc:
            error = str(exc)
    return render_template_string(HTML, report=report, error=error)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
