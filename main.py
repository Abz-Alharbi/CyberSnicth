"""
main.py — Entry point for deployment platforms.

Starts the bot loop in a background thread and runs a minimal
HTTP health-check server on port 8000 so the platform knows
the app is alive.
"""

import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logger = logging.getLogger("main")


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"CyberSnitch is running.")

    def log_message(self, format, *args):
        pass   # silence HTTP access logs


def run_health_server():
    port = int(os.getenv("PORT", 8000))
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    logger.info("Health server on port %d", port)
    server.serve_forever()


if __name__ == "__main__":
    # Start health server in background thread
    t = threading.Thread(target=run_health_server, daemon=True)
    t.start()

    # Run the bot (blocking — keeps the process alive)
    import bot
    bot.main()
