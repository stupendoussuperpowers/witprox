from flask import Flask, Response, render_template, stream_with_context
import time
import json
import os
import argparse

app = Flask(__name__)


def event_stream(filepath):
    """
    Generator that yields each JSON line from filepath as an SSE 'data:' chunk.
    It first emits existing lines, then tails the file for new lines.
    """
    # Ensure file exists
    open(filepath, "a").close()

    with open(filepath, "r", encoding="utf-8") as f:
        # Emit existing lines
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            # sanity: ensure it's JSON
            try:
                json.loads(line)
            except Exception:
                # skip invalid lines
                continue
            yield f"data: {line}\n\n"

        # Now tail the file for new lines
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.5)
                f.seek(where)
            else:
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    json.loads(line)
                except Exception:
                    continue
                yield f"data: {line}\n\n"


@app.route("/events")
def sse_events():
    # SSE stream; the browser will keep this connection open
    filepath = app.config.get("LOG_PATH", "records.log")
    return Response(stream_with_context(event_stream(filepath)),
                    mimetype="text/event-stream")


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live JSON log viewer (SSE)")
    parser.add_argument("--file", "-f", default="records.log",
                        help="newline JSON log file")
    parser.add_argument("--host", default="0.0.0.0", help="host to bind")
    parser.add_argument("--port", "-p", type=int,
                        default=8000, help="port to bind")
    args = parser.parse_args()

    app.config["LOG_PATH"] = os.path.abspath(args.file)
    print(f"Serving {app.config['LOG_PATH']
                     } on http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
