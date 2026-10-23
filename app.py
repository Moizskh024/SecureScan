
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import (
    BadRequest,
    HTTPException,
    RequestEntityTooLarge,
)

from scanner.validator import validate_url
from scanner.preflight import preflight_assess
from scanner.header_analyzer import analyze_security_headers


app = Flask(__name__)

# Limit incoming request bodies to 16 KB.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


def error_response(message, status_code, **extra):
    """Return a consistent JSON error response."""
    return jsonify({
        **extra,
        "error": message,
    }), status_code


def read_json_object(error_key):
    """Read a JSON object or return a safe JSON error response."""
    if not request.is_json:
        return None, error_response(
            "Send the request body as JSON.",
            415,
            **{error_key: False},
        )

    try:
        data = request.get_json(silent=False)
    except BadRequest:
        return None, error_response(
            "The request contains invalid JSON.",
            400,
            **{error_key: False},
        )

    if not isinstance(data, dict):
        return None, error_response(
            "The request body must be a JSON object.",
            400,
            **{error_key: False},
        )

    return data, None


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(_error):
    """Return a JSON response when a request exceeds the size limit."""
    return jsonify({
        "error": "Request body is too large. Maximum size is 16 KB."
    }), 413


@app.errorhandler(HTTPException)
def handle_http_error(error):
    """Return JSON errors for API paths and preserve normal page errors."""
    if request.path.startswith("/api/"):
        if error.code == 404:
            message = "API endpoint not found."
        elif error.code == 405:
            message = "HTTP method not allowed for this API endpoint."
        else:
            message = error.description

        return jsonify({
            "error": message,
        }), error.code

    # Keep Flask's normal HTML error response for non-API pages.
    return error


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Hide unexpected exception details from API clients."""
    if isinstance(error, HTTPException):
        return handle_http_error(error)

    app.logger.error(
        "Unexpected server error while handling %s %s",
        request.method,
        request.path,
    )

    return jsonify({
        "error": "An unexpected server error occurred."
    }), 500


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/validate", methods=["POST"])
def api_validate():
    data, error = read_json_object("valid")

    if error:
        return error

    if "url" not in data:
        return error_response(
            "The URL field is required.",
            400,
            valid=False,
        )

    return jsonify(validate_url(data["url"])), 200


@app.route("/api/preflight", methods=["POST"])
def api_preflight():
    data, error = read_json_object("safe")

    if error:
        response, status = error
        response_data = response.get_json()
        response_data["status"] = "rejected"

        return jsonify(response_data), status

    if "url" not in data:
        return jsonify({
            "safe": False,
            "status": "rejected",
            "error": "The URL field is required.",
        }), 400

    return jsonify(preflight_assess(data["url"])), 200


@app.route("/api/analyze-headers", methods=["POST"])
def api_analyze_headers():
    data, error = read_json_object("success")

    if error:
        return error

    if "headers" not in data:
        return error_response(
            "The headers field is required.",
            400,
            success=False,
        )

    try:
        result = analyze_security_headers(data["headers"])
    except TypeError as exc:
        return error_response(
            str(exc),
            400,
            success=False,
        )

    return jsonify({
        "success": True,
        **result,
    }), 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
