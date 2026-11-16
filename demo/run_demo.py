#!/usr/bin/env python3
"""Run the MOE console on this computer with sample data. No Wazuh server needed.

    python3 demo/run_demo.py            then open http://127.0.0.1:8443
    python3 demo/run_demo.py --port 9000

What it starts (all on 127.0.0.1, all stopped with Ctrl+C):
  * a stand-in for the Wazuh indexer and the Wazuh server API, filled with synthetic alerts and events;
  * the real console (console/app/moe_console.py) in demo mode, with sign-in off;
  * a feeder that writes one sample alert every few seconds, so the Live page moves.
The library's alerts in the sample are real engine output: each one was produced by replaying a regression case
through the Wazuh analysis engine. Needs Python 3.9 or newer and nothing else."""
import argparse, datetime, json, os, shutil, subprocess, sys, tempfile, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def wait_for(url, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return True
        except Exception as e:                      # an HTTP error still means the service answers
            if getattr(e, "code", None):
                return True
            time.sleep(0.3)
    return False


def feed(path, stop):
    """Append the library's sample alerts to the file the console follows, with the current time."""
    sample = [json.loads(l) for l in open(os.path.join(HERE, "sample-alerts.ndjson"), encoding="utf-8")]
    n = 0
    while not stop.is_set():
        for i, alert in enumerate(sample):
            now = datetime.datetime.now(datetime.timezone.utc)
            n += 1
            alert = dict(alert, timestamp=now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}+0000",
                         id=f"{int(now.timestamp())}.{900000 + n}")
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
            if stop.wait(0.2 if n <= 12 else 4):    # a first screenful at once, then one every few seconds
                return
        if stop.wait(60):
            return


def main():
    ap = argparse.ArgumentParser(description="MOE console demo with sample data")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="moe-demo-")
    procs, stop = [], threading.Event()
    try:
        data = os.path.join(work, "data")
        subprocess.run([sys.executable, os.path.join(HERE, "demo_data.py"), data], check=True, stdout=subprocess.DEVNULL)
        rules = os.path.join(work, "ossec", "etc", "rules")
        shutil.copytree(os.path.join(ROOT, "wazuh", "rules"), rules)
        os.makedirs(os.path.join(work, "ossec", "ruleset", "rules"))
        alerts = os.path.join(work, "alerts.json")
        open(alerts, "w").close()

        procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "mock_wazuh.py"), data, "-", "--plain"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        if not wait_for("http://127.0.0.1:19200/"):
            sys.exit("The stand-in server did not start. Is something else using port 19200 or 15500?")
        env = dict(os.environ, MOE_DEMO="1", MOE_AUTH="off", MOE_PLAIN_HTTP="1", MOE_BIND="127.0.0.1", MOE_PORT=str(args.port),
                   MOE_ALERTS=alerts, MOE_OSSEC_DIR=os.path.join(work, "ossec"), MOE_STATE_DIR=os.path.join(work, "state"),
                   MOE_INDEXER_URL="http://127.0.0.1:19200", MOE_INDEXER_USER="admin", MOE_INDEXER_PASS="demo-only-1A*",
                   MOE_API_URL="http://127.0.0.1:15500", MOE_API_USER="wazuh-wui", MOE_API_PASS="demo-only-1A*")
        os.makedirs(env["MOE_STATE_DIR"])
        procs.append(subprocess.Popen([sys.executable, os.path.join(ROOT, "console", "app", "moe_console.py")], env=env,
                                      stdout=subprocess.DEVNULL))
        url = f"http://127.0.0.1:{args.port}/"
        if not wait_for(url):
            sys.exit(f"The console did not start. Is something else using port {args.port}? Try --port 9000.")
        threading.Thread(target=feed, args=(alerts, stop), daemon=True).start()
        print(f"\n  MOE console demo is running:  {url}\n  Sample data only. Press Ctrl+C to stop.\n", flush=True)
        while all(p.poll() is None for p in procs):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(work, ignore_errors=True)
        print("Demo stopped.")


if __name__ == "__main__":
    main()
