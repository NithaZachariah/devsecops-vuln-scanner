from flask import Blueprint, render_template, request
from .scanner import run_scan

main = Blueprint("main", __name__)

@main.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            results = run_scan(url)
            if results.get("error"):
                error = results["error"]
                results = None

    return render_template("index.html", results=results, error=error)

@main.route("/health")
def health():
    """Health check endpoint used by Kubernetes liveness probe."""
    return {"status": "healthy"}, 200