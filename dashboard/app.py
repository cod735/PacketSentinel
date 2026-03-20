# dashboard/app.py
# PacketSentinel — Flask Dashboard Backend
# Provides all API endpoints for the frontend dashboard.

import csv
import time
import sqlite3
import io
from datetime import datetime, timedelta
from collections import deque, defaultdict
from flask import Flask, jsonify, render_template, Response, request
from config import DB_PATH, BLOCKLIST_PATH


# ── Traffic timeline storage ─────────────────────────────────
_traffic_timeline = deque(maxlen=60)
_last_timeline_tick = time.time()


def create_app(sniffer):
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )

    # ════════════════════════════════════════════════════════
    # ROUTE 1 — Serve dashboard HTML
    # ════════════════════════════════════════════════════════
    @app.route("/")
    def index():
        return render_template("index.html")

    # ════════════════════════════════════════════════════════
    # ROUTE 2 — Live alerts
    # ════════════════════════════════════════════════════════
    @app.route("/api/alerts")
    def get_alerts():
        try:
            severity  = request.args.get("severity", "ALL")
            search    = request.args.get("search", "").strip()
            limit     = int(request.args.get("limit", 100))

            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            query  = """
                SELECT timestamp, rule, src_ip, country,
                       country_code, detail, severity
                FROM alerts
                WHERE 1=1
            """
            params = []

            if severity != "ALL":
                query += " AND severity = ?"
                params.append(severity)

            if search:
                query += " AND (src_ip LIKE ? OR rule LIKE ? OR country LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            alerts = [
                {
                    "timestamp"    : r[0],
                    "rule"         : r[1],
                    "src_ip"       : r[2],
                    "country"      : r[3],
                    "country_code" : r[4],
                    "detail"       : r[5],
                    "severity"     : r[6],
                }
                for r in rows
            ]
            return jsonify({"alerts": alerts, "count": len(alerts)})

        except Exception as e:
            return jsonify({"alerts": [], "count": 0, "error": str(e)})

    # ════════════════════════════════════════════════════════
    # ROUTE 3 — Live stats
    # ════════════════════════════════════════════════════════
    @app.route("/api/stats")
    def get_stats():
        start = sniffer.stats.get("start_time", "")
        try:
            start_dt   = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
            uptime_sec = int((datetime.now() - start_dt).total_seconds())
            h, rem     = divmod(uptime_sec, 3600)
            m, s       = divmod(rem, 60)
            uptime_str = f"{h:02d}:{m:02d}:{s:02d}"
        except Exception:
            uptime_str = "00:00:00"

        # Threat level based on recent alerts
        threat_level = _calculate_threat_level()

        if sniffer.baseline.is_learning:
            baseline_status  = "learning"
            baseline_message = f"Learning... {sniffer.baseline.time_remaining()}s remaining"
        else:
            baseline_status  = "ready"
            baseline_message = f"Active — threshold: {sniffer.baseline.spike_threshold:.0f} pkt/s"

        # Top attacker IP
        top_ip = _get_top_ip()

        return jsonify({
            "total_packets"    : sniffer.stats.get("total_packets", 0),
            "total_alerts"     : sniffer.stats.get("total_alerts", 0),
            "packets_per_sec"  : sniffer.stats.get("packets_per_sec", 0),
            "uptime"           : uptime_str,
            "interface"        : sniffer.stats.get("interface", ""),
            "baseline_status"  : baseline_status,
            "baseline_message" : baseline_message,
            "threat_level"     : threat_level,
            "top_ip"           : top_ip,
        })

    # ════════════════════════════════════════════════════════
    # ROUTE 4 — Traffic timeline for chart
    # ════════════════════════════════════════════════════════
    @app.route("/api/traffic")
    def get_traffic():
        global _traffic_timeline, _last_timeline_tick
        now = time.time()
        if now - _last_timeline_tick >= 1.0:
            _traffic_timeline.append({
                "time"  : datetime.now().strftime("%H:%M:%S"),
                "value" : sniffer.stats.get("packets_per_sec", 0)
            })
            _last_timeline_tick = now
        return jsonify({"timeline": list(_traffic_timeline)})

    # ════════════════════════════════════════════════════════
    # ROUTE 5 — Export CSV
    # ════════════════════════════════════════════════════════
    @app.route("/api/export/csv")
    def export_csv():
        try:
            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, rule, src_ip, country,
                       country_code, detail, severity
                FROM alerts ORDER BY id DESC
            """)
            rows = cursor.fetchall()
            conn.close()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Timestamp", "Rule", "Source IP",
                "Country", "Country Code", "Detail", "Severity"
            ])
            for row in rows:
                writer.writerow(row)

            output.seek(0)
            filename = f"packetsentinel_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ════════════════════════════════════════════════════════
    # ROUTE 6 — Export JSON
    # ════════════════════════════════════════════════════════
    @app.route("/api/export/json")
    def export_json():
        try:
            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, rule, src_ip, country,
                       country_code, detail, severity
                FROM alerts ORDER BY id DESC
            """)
            rows = cursor.fetchall()
            conn.close()

            alerts = [
                {
                    "timestamp"    : r[0],
                    "rule"         : r[1],
                    "src_ip"       : r[2],
                    "country"      : r[3],
                    "country_code" : r[4],
                    "detail"       : r[5],
                    "severity"     : r[6],
                }
                for r in rows
            ]
            output   = io.StringIO()
            import json
            json.dump({"alerts": alerts, "exported_at": datetime.now().isoformat()}, output, indent=2)
            output.seek(0)
            filename = f"packetsentinel_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            return Response(
                output.getvalue(),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ════════════════════════════════════════════════════════
    # ROUTE 7 — Threat Intel
    # ════════════════════════════════════════════════════════
    @app.route("/api/threat-intel")
    def get_threat_intel():
        try:
            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Top countries by alert count
            cursor.execute("""
                SELECT country, country_code, COUNT(*) as count
                FROM alerts
                WHERE country != 'N/A' AND country != 'Private Network'
                GROUP BY country, country_code
                ORDER BY count DESC
                LIMIT 10
            """)
            countries = [
                {"country": r[0], "code": r[1], "count": r[2]}
                for r in cursor.fetchall()
            ]

            # Top IPs by alert count
            cursor.execute("""
                SELECT src_ip, country, country_code, COUNT(*) as count
                FROM alerts
                WHERE src_ip != 'N/A'
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10
            """)
            top_ips = [
                {"ip": r[0], "country": r[1], "code": r[2], "count": r[3]}
                for r in cursor.fetchall()
            ]

            conn.close()
            return jsonify({
                "top_countries" : countries,
                "top_ips"       : top_ips,
            })
        except Exception as e:
            return jsonify({"top_countries": [], "top_ips": [], "error": str(e)})

    # ════════════════════════════════════════════════════════
    # ROUTE 8 — Analytics
    # ════════════════════════════════════════════════════════
    @app.route("/api/analytics")
    def get_analytics():
        try:
            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Alerts per hour (last 24 hours)
            cursor.execute("""
                SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour ASC
            """)
            alerts_over_time = [
                {"hour": r[0], "count": r[1]}
                for r in cursor.fetchall()
            ]

            # Detection type breakdown
            cursor.execute("""
                SELECT rule, COUNT(*) as count
                FROM alerts
                GROUP BY rule
                ORDER BY count DESC
            """)
            detection_types = [
                {"rule": r[0], "count": r[1]}
                for r in cursor.fetchall()
            ]

            # Severity breakdown
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
                ORDER BY count DESC
            """)
            severity_breakdown = [
                {"severity": r[0], "count": r[1]}
                for r in cursor.fetchall()
            ]

            conn.close()
            return jsonify({
                "alerts_over_time"  : alerts_over_time,
                "detection_types"   : detection_types,
                "severity_breakdown": severity_breakdown,
            })
        except Exception as e:
            return jsonify({
                "alerts_over_time"  : [],
                "detection_types"   : [],
                "severity_breakdown": [],
                "error"             : str(e)
            })

    # ════════════════════════════════════════════════════════
    # ROUTE 9 — Block IP (add to blocklist)
    # ════════════════════════════════════════════════════════
    @app.route("/api/blocklist/add", methods=["POST"])
    def add_to_blocklist():
        try:
            data = request.get_json()
            ip   = data.get("ip", "").strip()

            if not ip:
                return jsonify({"success": False, "error": "No IP provided"}), 400

            # Add to blocklist file
            with open(BLOCKLIST_PATH, "a") as f:
                f.write(f"\n{ip}")

            # Also reload in detector
            sniffer.detector._blocklist.add(ip)

            return jsonify({"success": True, "message": f"{ip} added to blocklist"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    # ════════════════════════════════════════════════════════
    # HELPERS
    # ════════════════════════════════════════════════════════
    def _calculate_threat_level():
        """Calculate overall threat level from recent alerts."""
        try:
            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity, COUNT(*) FROM alerts
                WHERE timestamp >= datetime('now', '-10 minutes')
                GROUP BY severity
            """)
            rows = dict(cursor.fetchall())
            conn.close()

            if rows.get("CRITICAL", 0) > 0:
                return "CRITICAL"
            elif rows.get("HIGH", 0) > 2:
                return "HIGH"
            elif rows.get("MEDIUM", 0) > 5:
                return "MEDIUM"
            elif sum(rows.values()) > 0:
                return "LOW"
            return "NONE"
        except Exception:
            return "NONE"

    def _get_top_ip():
        """Get the most frequently alerting IP."""
        try:
            conn   = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT src_ip, country_code, COUNT(*) as count
                FROM alerts WHERE src_ip != 'N/A'
                GROUP BY src_ip ORDER BY count DESC LIMIT 1
            """)
            row = cursor.fetchone()
            conn.close()
            if row:
                return {"ip": row[0], "code": row[1], "count": row[2]}
            return {"ip": "—", "code": "—", "count": 0}
        except Exception:
            return {"ip": "—", "code": "—", "count": 0}

    return app