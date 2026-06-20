# Headless ONVIF Event Viewer Service

`onvif_event_viewer.py` is a service-oriented ONVIF pull-point event viewer. It runs without Tkinter, starts one worker thread for each enabled camera, and exposes browser-friendly status and management pages.

## Service startup

Create or edit `onvif_event_viewer_settings.json`, then start the service:

```bash
python3 onvif_event_viewer.py --settings onvif_event_viewer_settings.json
```

By default the service listens on `http://0.0.0.0:8088`. Set `httpHost` and `httpPort` in the settings file to change the bind address.

## Multi-camera configuration format

Top-level options act as defaults for all cameras. The `cameras` array contains per-camera entries. Only `ip` is required when adding or editing a camera; other fields may inherit defaults or remain blank.

```json
{
  "httpHost": "0.0.0.0",
  "httpPort": 8088,
  "pullIntervalSeconds": 2,
  "pullTimeoutSeconds": 10,
  "subscriptionTerminationTime": "PT1H",
  "eventFilter": "",
  "mqtt": {
    "enabled": false,
    "host": "localhost",
    "port": 1883,
    "username": "",
    "password": "",
    "topic": "onvif/events/{camera}"
  },
  "cameras": [
    {
      "enabled": true,
      "cameraName": "Front Door",
      "ip": "192.168.1.25",
      "username": "camera-user",
      "password": "camera-password",
      "eventFilter": "",
      "mqttTopic": "makerspace/cameras/front-door/events"
    }
  ]
}
```

Camera display names are resolved in this order: configured `cameraName`, ONVIF manufacturer/model friendly name, then hostname/IP. If two cameras resolve to the same friendly name, the status output falls back to IP addresses for uniqueness.

## Runtime behavior

Each enabled camera runs in its own daemon worker thread. A worker connects to ONVIF, discovers device information and event capabilities, creates a pull-point subscription, continuously pulls events, and records:

* connection status,
* last event timestamp,
* last event details.

Unreachable or connection-lost cameras retry with exponential backoff up to five minutes. Editing a camera recreates its worker and resets retry backoff. Authentication failures are marked as `authentication failed` and are not retried until the camera is edited.

## SSE endpoint

Real-time camera events are streamed with Server-Sent Events at:

* `GET /events`

Example browser usage:

```javascript
const source = new EventSource('/events');
source.onmessage = (message) => console.log(JSON.parse(message.data));
```

## Status pages

* `GET /status.json` returns a JSON list of cameras with connection status, last event timestamp, and last event details.
* `GET /status.html` renders the same status as an HTML table.

## Management pages

* `GET /manage.html` lists configured cameras and links to management actions.
* `GET /camera/add` adds a camera.
* `GET /camera/edit?id=<camera-id>` edits a camera.
* `GET /camera/delete?id=<camera-id>` deletes a camera.
* `GET /defaults/edit` edits service defaults such as HTTP bind options, pull intervals, subscription termination time, and event filters.

## MQTT configuration

MQTT publishing is optional. Install `paho-mqtt` if MQTT output is required:

```bash
python3 -m pip install paho-mqtt
```

Set `mqtt.enabled` to `true` and configure the broker fields. The default topic template is `onvif/events/{camera}`. Per-camera `mqttTopic` overrides the default topic. Topic templates may use `{camera}`, `{cameraId}`, and `{ip}` placeholders.
