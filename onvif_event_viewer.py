#!/usr/bin/env python3
"""Headless ONVIF event viewer service.

Provides a multi-camera ONVIF pull-point event service with JSON/HTML status,
management pages, and Server-Sent Events.  The implementation intentionally uses
only Python's standard library for the HTTP service and SOAP transport; MQTT is
optional and enabled when paho-mqtt is installed and configured.
"""
from __future__ import annotations

import argparse
import base64
import copy
import dataclasses
import datetime as dt
import hashlib
import html
import json
import queue
import random
import socket
import string
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SETTINGS_FILE = Path("onvif_event_viewer_settings.json")
SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
WSA_NS = "http://www.w3.org/2005/08/addressing"
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
TD_NS = "http://www.onvif.org/ver10/device/wsdl"
TEV_NS = "http://www.onvif.org/ver10/events/wsdl"

ET.register_namespace("s", SOAP_NS)
ET.register_namespace("wsa", WSA_NS)
ET.register_namespace("wsse", WSSE_NS)
ET.register_namespace("wsu", WSU_NS)
ET.register_namespace("tds", TD_NS)
ET.register_namespace("tev", TEV_NS)

DEFAULT_SETTINGS: Dict[str, Any] = {
    "httpHost": "0.0.0.0",
    "httpPort": 8088,
    "pullIntervalSeconds": 2,
    "pullTimeoutSeconds": 10,
    "subscriptionTerminationTime": "PT1H",
    "eventFilter": "",
    "mqtt": {
        "enabled": False,
        "host": "localhost",
        "port": 1883,
        "username": "",
        "password": "",
        "topic": "onvif/events/{camera}",
    },
    "cameras": [],
}

AUTH_FAILURE_MARKERS = ("not authorized", "unauthorized", "forbidden", "401", "403", "sender not authorized")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def deep_merge(defaults: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(defaults)
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def wsse_username_token(username: str, password: str) -> ET.Element:
    """Build a WS-Security UsernameToken with password digest."""
    security = ET.Element(f"{{{WSSE_NS}}}Security")
    token = ET.SubElement(security, f"{{{WSSE_NS}}}UsernameToken")
    ET.SubElement(token, f"{{{WSSE_NS}}}Username").text = username or ""
    nonce_bytes = bytes(random.getrandbits(8) for _ in range(20))
    created = iso_now().replace("+00:00", "Z")
    digest = base64.b64encode(hashlib.sha1(nonce_bytes + created.encode() + (password or "").encode()).digest()).decode()
    password_el = ET.SubElement(token, f"{{{WSSE_NS}}}Password")
    password_el.set("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest")
    password_el.text = digest
    nonce_el = ET.SubElement(token, f"{{{WSSE_NS}}}Nonce")
    nonce_el.set("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
    nonce_el.text = base64.b64encode(nonce_bytes).decode()
    ET.SubElement(token, f"{{{WSU_NS}}}Created").text = created
    return security


def soap_envelope(body: ET.Element, username: str = "", password: str = "", action: str = "", to: str = "") -> bytes:
    envelope = ET.Element(f"{{{SOAP_NS}}}Envelope")
    header = ET.SubElement(envelope, f"{{{SOAP_NS}}}Header")
    if action:
        ET.SubElement(header, f"{{{WSA_NS}}}Action").text = action
    if to:
        ET.SubElement(header, f"{{{WSA_NS}}}To").text = to
    ET.SubElement(header, f"{{{WSA_NS}}}MessageID").text = f"urn:uuid:{uuid.uuid4()}"
    if username:
        header.append(wsse_username_token(username, password))
    body_el = ET.SubElement(envelope, f"{{{SOAP_NS}}}Body")
    body_el.append(body)
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


class OnvifSoapClient:
    """Small ONVIF SOAP client used by each camera worker."""

    def __init__(self, host: str, username: str = "", password: str = "", timeout: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.device_url = f"http://{host}/onvif/device_service"

    def call(self, url: str, body: ET.Element, action: str = "") -> ET.Element:
        payload = soap_envelope(body, self.username, self.password, action, url)
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"'})
        with urllib.request.urlopen(req, timeout=self.timeout) as response:
            return ET.fromstring(response.read())

    def get_device_information(self) -> Dict[str, str]:
        body = ET.Element(f"{{{TD_NS}}}GetDeviceInformation")
        root = self.call(self.device_url, body, "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation")
        return {strip_ns(child.tag): child.text or "" for child in root.findall(".//") if strip_ns(child.tag) in {"Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"}}

    def get_capabilities(self) -> Dict[str, str]:
        body = ET.Element(f"{{{TD_NS}}}GetCapabilities")
        ET.SubElement(body, f"{{{TD_NS}}}Category").text = "All"
        root = self.call(self.device_url, body, "http://www.onvif.org/ver10/device/wsdl/GetCapabilities")
        capabilities: Dict[str, str] = {}
        for parent in root.findall(".//"):
            xaddr = next((child.text for child in list(parent) if strip_ns(child.tag) == "XAddr" and child.text), None)
            if xaddr:
                capabilities[strip_ns(parent.tag)] = xaddr
                capabilities.setdefault("XAddr", xaddr)
        return capabilities

    def create_pull_point_subscription(self, event_url: str, termination_time: str, event_filter: str = "") -> str:
        body = ET.Element(f"{{{TEV_NS}}}CreatePullPointSubscription")
        if event_filter:
            filter_el = ET.SubElement(body, f"{{{TEV_NS}}}Filter")
            filter_el.text = event_filter
        ET.SubElement(body, f"{{{TEV_NS}}}InitialTerminationTime").text = termination_time
        root = self.call(event_url, body, "http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest")
        for el in root.findall(".//"):
            if strip_ns(el.tag) == "Address" and el.text:
                return el.text
        raise RuntimeError("ONVIF subscription response did not include a pull-point address")

    def pull_messages(self, pullpoint_url: str, timeout_seconds: int, limit: int = 10) -> List[Dict[str, Any]]:
        body = ET.Element(f"{{{TEV_NS}}}PullMessages")
        ET.SubElement(body, f"{{{TEV_NS}}}Timeout").text = f"PT{timeout_seconds}S"
        ET.SubElement(body, f"{{{TEV_NS}}}MessageLimit").text = str(limit)
        root = self.call(pullpoint_url, body, "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest")
        return parse_onvif_events(root)


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def parse_onvif_events(root: ET.Element) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for msg in [el for el in root.findall(".//") if strip_ns(el.tag) == "NotificationMessage"]:
        event = {"receivedAt": iso_now(), "topic": "", "message": {}, "raw": ET.tostring(msg, encoding="unicode")[:4000]}
        for child in msg.iter():
            name = strip_ns(child.tag)
            if name == "Topic" and child.text:
                event["topic"] = child.text.strip()
            elif name in {"SimpleItem", "ElementItem"}:
                key = child.attrib.get("Name") or child.attrib.get("name") or name
                event["message"][key] = child.attrib.get("Value") or child.attrib.get("value") or (child.text or "")
        events.append(event)
    return events


@dataclasses.dataclass
class CameraConfig:
    id: str
    enabled: bool
    cameraName: str
    ip: str
    username: str = ""
    password: str = ""
    eventFilter: str = ""
    mqttTopic: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any], defaults: Dict[str, Any]) -> "CameraConfig":
        if not data.get("ip"):
            raise ValueError("camera ip is required")
        return cls(id=data.get("id") or str(uuid.uuid4()), enabled=bool(data.get("enabled", True)), cameraName=data.get("cameraName", ""), ip=data["ip"], username=data.get("username", defaults.get("username", "")), password=data.get("password", defaults.get("password", "")), eventFilter=data.get("eventFilter", defaults.get("eventFilter", "")), mqttTopic=data.get("mqttTopic", ""))


class SettingsStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.settings = self.load()

    def load(self) -> Dict[str, Any]:
        if self.path.exists():
            return deep_merge(DEFAULT_SETTINGS, json.loads(self.path.read_text()))
        return copy.deepcopy(DEFAULT_SETTINGS)

    def save(self) -> None:
        with self.lock:
            self.path.write_text(json.dumps(self.settings, indent=2) + "\n")

    def cameras(self) -> List[CameraConfig]:
        with self.lock:
            return [CameraConfig.from_dict(c, self.settings) for c in self.settings.get("cameras", []) if c.get("ip")]


class EventBus:
    def __init__(self):
        self.clients: List[queue.Queue] = []
        self.lock = threading.Lock()

    def publish(self, event: Dict[str, Any]) -> None:
        with self.lock:
            for client in list(self.clients):
                client.put(event)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self.lock:
            self.clients.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.clients:
                self.clients.remove(q)


class MqttPublisher:
    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings.get("mqtt", {})
        self.client = None
        if self.settings.get("enabled"):
            try:
                import paho.mqtt.client as mqtt  # type: ignore
                self.client = mqtt.Client()
                if self.settings.get("username"):
                    self.client.username_pw_set(self.settings.get("username"), self.settings.get("password") or None)
                self.client.connect(self.settings.get("host", "localhost"), int(self.settings.get("port", 1883)), 60)
                self.client.loop_start()
            except Exception as exc:
                print(f"MQTT disabled: {exc}")
                self.client = None

    def publish(self, cfg: CameraConfig, display_name: str, event: Dict[str, Any]) -> None:
        if not self.client:
            return
        topic_template = cfg.mqttTopic or self.settings.get("topic", "onvif/events/{camera}")
        topic = topic_template.format(camera=display_name, cameraId=cfg.id, ip=cfg.ip)
        self.client.publish(topic, json.dumps(event))


class CameraWorker(threading.Thread):
    def __init__(self, cfg: CameraConfig, defaults: Dict[str, Any], bus: EventBus, mqtt: MqttPublisher):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.defaults = defaults
        self.bus = bus
        self.mqtt = mqtt
        self.stop_event = threading.Event()
        self.status = {"id": cfg.id, "ip": cfg.ip, "displayName": cfg.cameraName or cfg.ip, "connectionStatus": "starting", "lastEventTimestamp": None, "lastEventDetails": None}

    def run(self) -> None:
        backoff = 1
        while not self.stop_event.is_set():
            try:
                self.status["connectionStatus"] = "connecting"
                client = OnvifSoapClient(self.cfg.ip, self.cfg.username, self.cfg.password, int(self.defaults.get("pullTimeoutSeconds", 10)))
                info = client.get_device_information()
                friendly = " ".join(p for p in [info.get("Manufacturer"), info.get("Model")] if p).strip()
                self.status["displayName"] = self.cfg.cameraName or friendly or self.cfg.ip
                caps = client.get_capabilities()
                event_url = caps.get("XAddr") or f"http://{self.cfg.ip}/onvif/event_service"
                pullpoint = client.create_pull_point_subscription(event_url, self.defaults.get("subscriptionTerminationTime", "PT1H"), self.cfg.eventFilter)
                self.status["connectionStatus"] = "connected"
                backoff = 1
                while not self.stop_event.is_set():
                    for event in client.pull_messages(pullpoint, int(self.defaults.get("pullTimeoutSeconds", 10))):
                        event.update({"cameraId": self.cfg.id, "camera": self.status["displayName"], "ip": self.cfg.ip})
                        self.status["lastEventTimestamp"] = event["receivedAt"]
                        self.status["lastEventDetails"] = event
                        self.bus.publish(event)
                        self.mqtt.publish(self.cfg, self.status["displayName"], event)
                    time.sleep(float(self.defaults.get("pullIntervalSeconds", 2)))
            except Exception as exc:
                message = str(exc)
                if any(marker in message.lower() for marker in AUTH_FAILURE_MARKERS):
                    self.status["connectionStatus"] = "authentication failed"
                    self.status["lastError"] = message
                    return
                self.status["connectionStatus"] = f"retrying in {backoff}s"
                self.status["lastError"] = message
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 300)

    def stop(self) -> None:
        self.stop_event.set()


class CameraManager:
    def __init__(self, store: SettingsStore, bus: EventBus):
        self.store = store
        self.bus = bus
        self.lock = threading.RLock()
        self.workers: Dict[str, CameraWorker] = {}
        self.mqtt = MqttPublisher(store.settings)

    def sync(self) -> None:
        with self.lock:
            configs = {c.id: c for c in self.store.cameras() if c.enabled}
            for cid in list(self.workers):
                if cid not in configs:
                    self.workers.pop(cid).stop()
            for cid, cfg in configs.items():
                if cid not in self.workers:
                    worker = CameraWorker(cfg, self.store.settings, self.bus, self.mqtt)
                    self.workers[cid] = worker
                    worker.start()

    def status(self) -> List[Dict[str, Any]]:
        with self.lock:
            configured = {c.id: c for c in self.store.cameras()}
            statuses = []
            used_names: Dict[str, int] = {}
            for cfg in configured.values():
                st = copy.deepcopy(self.workers[cfg.id].status) if cfg.id in self.workers else {"id": cfg.id, "ip": cfg.ip, "displayName": cfg.cameraName or cfg.ip, "connectionStatus": "disabled", "lastEventTimestamp": None, "lastEventDetails": None}
                st["enabled"] = cfg.enabled
                used_names[st["displayName"]] = used_names.get(st["displayName"], 0) + 1
                statuses.append(st)
            for st in statuses:
                if used_names.get(st["displayName"], 0) > 1:
                    st["displayName"] = st["ip"]
            return statuses


def make_handler(store: SettingsStore, manager: CameraManager, bus: EventBus):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/events":
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Cache-Control", "no-cache"); self.end_headers()
                q = bus.subscribe()
                try:
                    while True:
                        event = q.get(timeout=30) if not q.empty() else {"heartbeat": iso_now()}
                        self.wfile.write(f"data: {json.dumps(event)}\n\n".encode()); self.wfile.flush(); time.sleep(1)
                except Exception:
                    bus.unsubscribe(q)
            elif path == "/status.json":
                self.json(manager.status())
            elif path in {"/", "/status.html"}:
                rows = "".join(f"<tr><td>{html.escape(s['displayName'])}</td><td>{html.escape(s['ip'])}</td><td>{html.escape(s['connectionStatus'])}</td><td>{html.escape(str(s.get('lastEventTimestamp') or ''))}</td><td><pre>{html.escape(json.dumps(s.get('lastEventDetails'), indent=2))}</pre></td></tr>" for s in manager.status())
                self.html(f"<h1>ONVIF Camera Status</h1><p><a href='/manage.html'>Manage cameras</a> | <a href='/events'>SSE events</a></p><table border='1'><tr><th>Name</th><th>IP</th><th>Status</th><th>Last event</th><th>Details</th></tr>{rows}</table>")
            elif path == "/manage.html":
                rows = "".join(f"<tr><td>{html.escape(c.get('cameraName') or c.get('ip',''))}</td><td>{html.escape(c.get('ip',''))}</td><td>{c.get('enabled', True)}</td><td><a href='/camera/edit?id={c.get('id','')}'>Edit</a> <a href='/camera/delete?id={c.get('id','')}'>Delete</a></td></tr>" for c in store.settings.get("cameras", []))
                self.html(f"<h1>Manage ONVIF Cameras</h1><p><a href='/camera/add'>Add camera</a> | <a href='/defaults/edit'>Edit defaults</a> | <a href='/status.html'>Status</a></p><table border='1'>{rows}</table>")
            elif path in {"/camera/add", "/camera/edit"}:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query); cid = qs.get("id", [""])[0]
                cam = next((c for c in store.settings.get("cameras", []) if c.get("id") == cid), {})
                self.html(form_camera(cam))
            elif path == "/camera/delete":
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query); cid = qs.get("id", [""])[0]
                store.settings["cameras"] = [c for c in store.settings.get("cameras", []) if c.get("id") != cid]; store.save(); manager.sync(); self.redirect("/manage.html")
            elif path == "/defaults/edit":
                self.html(form_defaults(store.settings))
            else:
                self.send_error(404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0")); data = urllib.parse.parse_qs(self.rfile.read(length).decode())
            path = urllib.parse.urlparse(self.path).path
            if path == "/camera/save":
                cam = {k: data.get(k, [""])[0] for k in ["id", "cameraName", "ip", "username", "password", "eventFilter", "mqttTopic"]}; cam["enabled"] = data.get("enabled", [""])[0] == "on"; cam["id"] = cam["id"] or str(uuid.uuid4())
                if not cam["ip"]: self.send_error(400, "ip is required"); return
                cams = [c for c in store.settings.get("cameras", []) if c.get("id") != cam["id"]]; cams.append(cam); store.settings["cameras"] = cams; store.save(); manager.sync(); self.redirect("/manage.html")
            elif path == "/defaults/save":
                for key in ["httpHost", "httpPort", "pullIntervalSeconds", "pullTimeoutSeconds", "subscriptionTerminationTime", "eventFilter"]:
                    store.settings[key] = data.get(key, [store.settings.get(key, "")])[0]
                store.save(); manager.sync(); self.redirect("/manage.html")
            else: self.send_error(404)

        def json(self, obj):
            payload = json.dumps(obj, indent=2).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def html(self, body):
            payload = ("<!doctype html><meta charset='utf-8'><title>ONVIF Event Viewer</title>" + body).encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def redirect(self, location):
            self.send_response(303); self.send_header("Location", location); self.end_headers()
    return Handler


def input_field(name, value="", typ="text"):
    return f"<label>{name}<input type='{typ}' name='{name}' value='{html.escape(str(value or ''))}'></label><br>"

def form_camera(cam):
    return "<h1>Camera</h1><form method='post' action='/camera/save'>" + input_field("id", cam.get("id", ""), "hidden") + "<label>enabled<input type='checkbox' name='enabled' checked></label><br>" + "".join(input_field(k, cam.get(k, ""), "password" if k == "password" else "text") for k in ["cameraName", "ip", "username", "password", "eventFilter", "mqttTopic"]) + "<button>Save</button></form>"

def form_defaults(settings):
    return "<h1>Defaults</h1><form method='post' action='/defaults/save'>" + "".join(input_field(k, settings.get(k, "")) for k in ["httpHost", "httpPort", "pullIntervalSeconds", "pullTimeoutSeconds", "subscriptionTerminationTime", "eventFilter"]) + "<button>Save</button></form>"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the headless ONVIF event viewer service")
    parser.add_argument("--settings", default=str(SETTINGS_FILE))
    args = parser.parse_args()
    store = SettingsStore(Path(args.settings)); bus = EventBus(); manager = CameraManager(store, bus); manager.sync()
    host, port = store.settings.get("httpHost", "0.0.0.0"), int(store.settings.get("httpPort", 8088))
    print(f"ONVIF event viewer listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), make_handler(store, manager, bus)).serve_forever()


if __name__ == "__main__":
    main()
