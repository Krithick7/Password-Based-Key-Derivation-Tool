from flask import Flask, render_template_string, request

from password_kdf_module import DEFAULT_SALT_LENGTH, PasswordKDFError, generate_password_report

app = Flask(__name__)

HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Password KDF Tester</title>
  <style>
    :root { --bg:#f2f6ff; --card:#ffffff; --text:#1b2340; --muted:#5f6b88; --accent:#2962ff; --danger:#d32f2f; --border:#d8e1f1; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background: radial-gradient(circle at top left,#eef4ff 0%,var(--bg) 60%); color:var(--text); display:flex; justify-content:center; align-items:center; padding:1rem; }
    .card { width:min(100%,760px); background:var(--card); border:1px solid var(--border); border-radius:16px; box-shadow:0 12px 28px rgba(15,30,90,0.12); padding:1.6rem; }
    h2 { margin-top:0; color:#1d2b5a; }
    .hint { margin:0 0 0.8rem; font-size:0.92rem; color:var(--muted); }
    form { display:grid; gap:0.8rem; }
    label { font-weight:600; margin-bottom:0.2rem; display:block; }
    input[type=password],input[type=number] { width:100%; border:1px solid var(--border); border-radius:10px; padding:0.72rem; transition:border-color 0.2s ease; font-size:1rem; }
    input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 4px rgba(41,98,255,0.12); }
    .actions { display:flex; gap:0.8rem; align-items:center; flex-wrap:wrap; }
    button { background:var(--accent); color:#fff; border:none; border-radius:10px; padding:0.75rem 1.2rem; font-weight:600; cursor:pointer; transition:transform 0.15s ease,opacity 0.15s ease; }
    button:hover { transform:translateY(-1px); opacity:0.95; }
    .error { color:var(--danger); background:rgba(211,47,47,0.1); border:1px solid rgba(211,47,47,0.2); border-radius:9px; font-weight:600; padding:0.75rem; }
    .report-card { background:#f7f9ff; border:1px solid #dce4f8; border-radius:10px; padding:1rem 1.1rem; margin-top:0.8rem; box-shadow:0 5px 12px rgba(13,33,90,0.08); }
    .report-title { margin:0 0 0.6rem; font-size:1.05rem; color:#233467; }
    .report-grid { display:grid; gap:0.6rem; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .report-item { background:#fff; border:1px solid #d8e1f1; border-radius:8px; padding:0.65rem 0.75rem; }
    .report-item strong { display:block; font-size:0.86rem; color:#4d5a85; }
    .report-item span { margin-top:0.2rem; display:block; font-size:1rem; font-weight:700; color:#1e2b5c; }
    .recommendations { margin-top:0.8rem; font-size:0.94rem; }
    .recommendations li { margin-bottom:0.3rem; }
    @media (max-width:560px) { .card { padding:1rem; } button { width:100%; } .actions { flex-direction:column; } }
  </style>
</head>
<body>
  <div class="card">
    <h2>Password KDF Local Tester</h2>
    <p class="hint">Enter your password and optional salt length; leave blank to use default salt length.</p>
    <form method="post">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autocomplete="new-password" />

      <label for="salt_length">Salt length (bytes)</label>
      <input id="salt_length" name="salt_length" type="number" min="16" placeholder="{{ default_salt_length }}" />

      <div class="actions">
        <button type="submit">Analyze Password</button>
      </div>
    </form>

    {% if error %}
      <div class="error">{{ error }}</div>
    {% endif %}

    {% if report %}
      <div class="report-card">
        <h3 class="report-title">Analysis Result</h3>
        <div class="report-grid">
          <div class="report-item"><strong>PBKDF2 key length</strong><span>{{ report["pbkdf2_key_length"] }}</span></div>
          <div class="report-item"><strong>PBKDF2 verify</strong><span>{{ report["pbkdf2_verify"] }}</span></div>
          <div class="report-item"><strong>bcrypt verify</strong><span>{{ report["bcrypt_verify"] }}</span></div>
          <div class="report-item"><strong>scrypt key length</strong><span>{{ report["scrypt_key_length"] }}</span></div>
          <div class="report-item"><strong>scrypt verify</strong><span>{{ report["scrypt_verify"] }}</span></div>
          <div class="report-item"><strong>Strength score</strong><span>{{ report["strength_score"] }}/100</span></div>
          <div class="report-item"><strong>Strength rating</strong><span>{{ report["strength_rating"] }}</span></div>
          <div class="report-item"><strong>Entropy bits</strong><span>{{ report["entropy_bits"] }}</span></div>
        </div>

        <div class="recommendations">
          <strong>Recommendations</strong>
          <ul>
            {% for r in report["recommendations"] %}
              <li>{{ r }}</li>
            {% endfor %}
          </ul>
        </div>

        <div class="report-item" style="margin-top:0.8rem;"><strong>bcrypt hash</strong><span>{{ report["bcrypt_hash"] }}</span></div>
      </div>
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
        salt_length = DEFAULT_SALT_LENGTH
        salt_length_raw = request.form.get("salt_length", "").strip()

        if salt_length_raw:
            try:
                salt_length = int(salt_length_raw)
            except (ValueError, TypeError):
                error = "Salt length must be a valid integer."

        if not error:
            try:
                report = generate_password_report(password, salt_length=salt_length)
            except PasswordKDFError as exc:
                error = str(exc)
    return render_template_string(
        HTML,
        report=report,
        error=error,
        default_salt_length=DEFAULT_SALT_LENGTH,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

