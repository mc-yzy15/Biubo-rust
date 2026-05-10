# Biubo WAF Plugin System

> Extend Biubo WAF with custom detection rules and log exporters. Build, share, and deploy community-driven security plugins.

---

## Table of Contents

1. [Overview](#overview)
2. [Directory Structure](#directory-structure)
3. [Plugin Architecture](#plugin-architecture)
4. [Detection Plugin Format](#detection-plugin-format)
5. [Exporter Plugin Format](#exporter-plugin-format)
6. [Creating a Detection Plugin](#creating-a-detection-plugin)
7. [Creating an Exporter Plugin](#creating-an-exporter-plugin)
8. [Plugin Lifecycle](#plugin-lifecycle)
9. [API Endpoints](#api-endpoints)
10. [Troubleshooting](#troubleshooting)

---

## Overview

Biubo WAF uses a **file-based JSON plugin system** that allows you to extend the WAF without writing Rust code. Plugins are loaded at startup from designated directories and can be enabled, disabled, reloaded, or removed at runtime via REST API.

**Key Features:**
- Zero-code plugin development (JSON-only configuration)
- Hot-reload support without restarting the WAF
- Two plugin types: Detection rules and Log exporters
- Thread-safe registry with atomic state management
- Automatic queue-based batching for exporter plugins
- Built-in retry logic with exponential backoff for exporters

**Plugin Types:**

| Type | Purpose | Config Location |
|------|---------|-----------------|
| Detection | Pattern-based attack detection | `plugins/detection/` |
| Exporter | Log forwarding to external systems | `plugins/exporters/` |

---

## Directory Structure

```
plugins/
├── README.md                 # This file
├── detection/                # Detection rule plugins (.json)
│   ├── sqli_custom.json
│   ├── xss_custom.json
│   └── my_custom_rule.json
├── exporters/                # Log exporter plugins (.json)
│   ├── siem_exporter.json
│   └── webhook_exporter.json
└── examples/                 # Example plugins for reference
    ├── detection_rule_example.json
    └── exporter_example.json
```

The `PluginLoader` scans both `plugins/detection/` and `plugins/exporters/` directories for `.json` files. Directories are created automatically on first startup if they don't exist.

---

## Plugin Architecture

### Plugin Loading Flow

```
Startup
  └─ init_plugins()
       └─ PluginLoader::new()
            └─ PluginRegistry::load_from_directory()
                 └─ scan_plugins() [detection/ + exporters/]
                      └─ load_plugin_file() [parse + validate]
                           └─ PluginRegistry::register()
```

### Runtime Flow

1. **Detection Plugins**: Enabled detection plugins' patterns are merged into the WAF engine's rule set by `get_plugin_detection_rules()`, grouped by `attack_type`.
2. **Exporter Plugins**: Enabled exporter plugins are registered with the `ExporterQueue`. Log entries are queued via `trigger_exporters()` and flushed in batches by the background worker.

### Auto-Reload

The `PluginLoader` monitors plugin directories with a **30-second scan interval**. When `should_reload()` returns true, calling the reload API will rescan and update the registry while preserving plugin states.

---

## Detection Plugin Format

### JSON Schema

```json
{
  "metadata": {
    "name": "<string>",
    "version": "<string>",
    "description": "<string>",
    "author": "<string>",
    "type": "detection"
  },
  "config": {
    "patterns": ["<regex_pattern_1>", "<regex_pattern_2>", "..."],
    "attack_type": "<string>"
  }
}
```

### Field Descriptions

#### Metadata (required)

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique plugin identifier. Must be unique across all plugins. |
| `version` | string | Semantic version string (e.g., `1.0.0`). |
| `description` | string | Human-readable description of what the plugin does. |
| `author` | string | Plugin author name or handle. |
| `type` | string | Must be `detection`. |

#### Config (required)

| Field | Type | Description |
|-------|------|-------------|
| `patterns` | array[string] | List of regex patterns to match against incoming requests. At least one pattern required. |
| `attack_type` | string | Classification label for detected attacks (e.g., `sqli`, `xss`, `bot_detection`). |

### Validation Rules

- `name` cannot be empty
- `version` cannot be empty
- `patterns` array must contain at least one pattern
- `attack_type` cannot be empty
- `type` must be `detection`

---

## Exporter Plugin Format

### JSON Schema

```json
{
  "metadata": {
    "name": "<string>",
    "version": "<string>",
    "description": "<string>",
    "author": "<string>",
    "type": "exporter"
  },
  "config": {
    "export_endpoint": "<url>",
    "format": "<string>",
    "batch_size": <integer>
  }
}
```

### Field Descriptions

#### Metadata (required)

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique plugin identifier. Must be unique across all plugins. |
| `version` | string | Semantic version string (e.g., `1.0.0`). |
| `description` | string | Human-readable description of what the plugin does. |
| `author` | string | Plugin author name or handle. |
| `type` | string | Must be `exporter`. |

#### Config (required)

| Field | Type | Description |
|-------|------|-------------|
| `export_endpoint` | string | Full URL of the target endpoint (e.g., `https://siem.example.com/api/logs`). Must not be empty. |
| `format` | string | Data format for export (e.g., `json`, `cef`, `syslog`). Must not be empty. |
| `batch_size` | integer | Number of log entries per batch. Default: `10` if set to 0. |

### Validation Rules

- `name` cannot be empty
- `version` cannot be empty
- `export_endpoint` cannot be empty
- `format` cannot be empty
- `type` must be `exporter`

### Exporter Behavior

- Logs are queued in a **channel-based queue** (default capacity: 1000)
- Batch flushing occurs on **interval** (1 second) or when `batch_size` is reached
- Failed exports are retried up to **3 times** with exponential backoff (500ms initial delay)
- HTTP timeout: 30 seconds
- Payload is sent as JSON array via POST request

---

## Creating a Detection Plugin

### Step 1: Choose a Directory

Place your detection plugin in `plugins/detection/`:

```bash
mkdir -p plugins/detection
```

### Step 2: Create the Plugin File

Create a new JSON file (e.g., `plugins/detection/custom_bot_detection.json`):

```json
{
  "metadata": {
    "name": "custom_bot_detection",
    "version": "1.0.0",
    "description": "Detects automated bot traffic by identifying suspicious user-agent patterns and rapid sequential requests",
    "author": "your-name",
    "type": "detection"
  },
  "config": {
    "patterns": [
      "(?i)(bot|crawler|spider|scraper)",
      "(?i)python-requests/",
      "(?i)curl/",
      "(?i)wget/",
      "(?i)go-http-client",
      "(?i)java/"
    ],
    "attack_type": "bot_detection"
  }
}
```

### Step 3: Validate the Plugin

Ensure the JSON is valid and all required fields are present. The WAF will log errors if validation fails:

```
ERROR Failed to load plugin from plugins/detection/custom_bot_detection.json: <error_message>
```

### Step 4: Deploy the Plugin

Place the file in the `plugins/detection/` directory. The plugin will be loaded on next startup or via the reload API.

### Step 5: Enable the Plugin

Plugins start in `Loaded` status. Enable via API:

```bash
curl -X POST http://localhost:8080/api/plugins/custom_bot_detection/enable
```

### Step 6: Verify

```bash
curl http://localhost:8080/api/plugins/
```

The plugin should appear in the list with `status: "enabled"`.

---

## Creating an Exporter Plugin

### Step 1: Choose a Directory

Place your exporter plugin in `plugins/exporters/`:

```bash
mkdir -p plugins/exporters
```

### Step 2: Create the Plugin File

Create a new JSON file (e.g., `plugins/exporters/siem_exporter.json`):

```json
{
  "metadata": {
    "name": "siem_exporter",
    "version": "1.0.0",
    "description": "Exports WAF logs to a centralized SIEM system for correlation and alerting",
    "author": "your-name",
    "type": "exporter"
  },
  "config": {
    "export_endpoint": "https://siem.example.com/api/v1/logs",
    "format": "json",
    "batch_size": 50
  }
}
```

### Step 3: Deploy the Plugin

Place the file in the `plugins/exporters/` directory.

### Step 4: Enable the Plugin

```bash
curl -X POST http://localhost:8080/api/plugins/siem_exporter/enable
```

### Step 5: Verify Export

After enabling, logs will be queued and exported automatically. Check logs for:

```
INFO Starting exporter worker with 1 exporter(s)
DEBUG Exported 50 log entries to https://siem.example.com/api/v1/logs
```

---

## Plugin Lifecycle

### States

```
Loaded ──enable()──▶ Enabled
                    │
                    ──disable()──▶ Disabled
                    │
                    ──error()──▶ Error("message")
```

| State | Description |
|-------|-------------|
| `Loaded` | Plugin file parsed successfully, not yet active |
| `Enabled` | Plugin is active and processing requests |
| `Disabled` | Plugin is inactive, rules/exporters not applied |
| `Error` | Plugin encountered a validation or runtime error |

### Lifecycle Operations

#### Enable

```bash
POST /api/plugins/{name}/enable
```

Transitions plugin from `Loaded` or `Disabled` to `Enabled`.

#### Disable

```bash
POST /api/plugins/{name}/disable
```

Transitions plugin from `Enabled` to `Disabled`.

#### Reload

```bash
POST /api/plugins/reload
```

Rescans plugin directories, updates plugin definitions, and preserves existing plugin states.

#### Update Config

```bash
PUT /api/plugins/{name}/config
Content-Type: application/json

{
  "config": {
    "key": "value"
  }
}
```

Updates plugin configuration at runtime.

#### Remove

```bash
DELETE /api/plugins/{name}
```

Unregisters the plugin and deletes the plugin file from disk.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/plugins/` | List all plugins |
| `POST` | `/api/plugins/{name}/enable` | Enable a plugin |
| `POST` | `/api/plugins/{name}/disable` | Disable a plugin |
| `PUT` | `/api/plugins/{name}/config` | Update plugin configuration |
| `DELETE` | `/api/plugins/{name}` | Remove a plugin |
| `POST` | `/api/plugins/reload` | Reload all plugins from disk |

### List Plugins

```bash
GET /api/plugins/
```

**Response:**

```json
{
  "status": "success",
  "data": [
    {
      "name": "custom_bot_detection",
      "version": "1.0.0",
      "description": "Detects automated bot traffic",
      "author": "your-name",
      "type": "detection",
      "status": "enabled",
      "config": {
        "type": "detection",
        "patterns": ["(?i)(bot|crawler)"],
        "attack_type": "bot_detection"
      }
    }
  ],
  "total": 1
}
```

### Enable Plugin

```bash
POST /api/plugins/custom_bot_detection/enable
```

**Response:**

```json
{
  "status": "success",
  "message": "Plugin 'custom_bot_detection' enabled"
}
```

### Disable Plugin

```bash
POST /api/plugins/custom_bot_detection/disable
```

**Response:**

```json
{
  "status": "success",
  "message": "Plugin 'custom_bot_detection' disabled"
}
```

### Update Plugin Config

```bash
PUT /api/plugins/custom_bot_detection/config
Content-Type: application/json

{
  "config": {
    "patterns": ["(?i)(bot|crawler|spider)"],
    "attack_type": "bot_detection_v2"
  }
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Configuration for plugin 'custom_bot_detection' updated"
}
```

### Remove Plugin

```bash
DELETE /api/plugins/custom_bot_detection
```

**Response:**

```json
{
  "status": "success",
  "message": "Plugin 'custom_bot_detection' removed"
}
```

### Reload Plugins

```bash
POST /api/plugins/reload
```

**Response:**

```json
{
  "status": "success",
  "message": "Reloaded 3 plugins",
  "count": 3
}
```

---

## Troubleshooting

### Plugin Not Loading

**Symptom:** Plugin doesn't appear in the list after startup.

**Causes:**
1. File is not in the correct directory (`plugins/detection/` or `plugins/exporters/`)
2. JSON is malformed
3. Required fields are missing or empty
4. Plugin name conflicts with an existing plugin

**Solution:**
- Check WAF logs for errors: `grep "Failed to load plugin" logs/`
- Validate JSON syntax: `cat plugins/detection/my_plugin.json | python3 -m json.tool`
- Verify all required fields are present and non-empty

### Plugin in Error State

**Symptom:** Plugin status shows `error: <message>`.

**Causes:**
1. Invalid pattern syntax in detection plugin
2. Invalid URL in exporter endpoint
3. Config type mismatch (e.g., exporter config for a detection plugin)

**Solution:**
- Review the error message in the plugin status
- Fix the configuration
- Reload the plugin: `POST /api/plugins/reload`

### Exporter Not Sending Logs

**Symptom:** Logs are not appearing in the target system.

**Causes:**
1. Exporter plugin is not enabled
2. Target endpoint is unreachable
3. HTTP timeout or connection refused

**Solution:**
- Verify exporter is enabled: `GET /api/plugins/`
- Test endpoint connectivity: `curl -X POST <export_endpoint>`
- Check WAF logs for retry attempts and failures

### Plugin Name Already Registered

**Symptom:** `Plugin '<name>' already registered` error.

**Causes:**
- Another plugin with the same name exists in a different directory

**Solution:**
- Ensure each plugin has a unique name across all plugin types
- Use descriptive, namespaced names (e.g., `team_name_rule_name`)

### Changes Not Taking Effect After Edit

**Symptom:** Modified plugin file but changes aren't reflected.

**Causes:**
- Plugin system hasn't auto-reloaded yet (30-second interval)
- Plugin file not saved or has JSON syntax errors

**Solution:**
- Trigger manual reload: `POST /api/plugins/reload`
- Verify the file is valid JSON
- Check that the plugin name matches exactly

---

## Best Practices

1. **Version your plugins**: Use semantic versioning to track changes
2. **Test patterns thoroughly**: Use tools like regex101.com to validate detection patterns
3. **Use descriptive names**: Prefix with your team or project name
4. **Document your plugins**: Include clear descriptions and author information
5. **Batch wisely**: Set `batch_size` based on your endpoint's throughput capacity
6. **Monitor exporter health**: Check logs for failed export attempts
7. **Keep plugins focused**: One attack type per detection plugin for maintainability
