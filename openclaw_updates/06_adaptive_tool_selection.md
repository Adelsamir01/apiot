# 06 — Adaptive Tool Selection and Dynamic Tool Registry

## Problem

APIOT's tool registry is static — the same 13 tools are available every session regardless of context. The `execute_exploit` enum is hardcoded. When the agent creates a tool via `create_tool`, it's registered in-memory only and lost on restart. There is no feedback loop where the agent learns which tools work best against which device types.

## What OpenClaw Does

OpenClaw's plugin system allows runtime tool registration via `api.registerTool()`. Tools have metadata (description, schema) and are dynamically available to the LLM. The skill system provides progressive disclosure — tool descriptions are always in context, but full schemas only load when relevant.

## How APIOT Should Implement This

### Dynamic Tool Registry with Persistence

```python
# core/tool_registry.py

class DynamicToolRegistry:
    """Manages static + dynamic tools with persistence and effectiveness tracking."""
    
    def __init__(self, db_path="data/memory.db"):
        self.static_tools = TOOL_SCHEMAS  # built-in tools
        self.dynamic_tools = {}           # runtime-created tools
        self._load_persisted_tools()      # load from DB
    
    def register(self, name, schema, code_path, metadata):
        """Register a dynamically created tool and persist it."""
        self.dynamic_tools[name] = {
            "schema": schema,
            "code_path": code_path,
            "metadata": metadata,
            "created_at": time.time(),
            "usage_count": 0,
            "success_count": 0,
        }
        self._persist(name)
    
    def get_schemas(self, device_profile=None):
        """Return tool schemas, optionally filtered by relevance to device."""
        schemas = list(self.static_tools)
        for name, tool in self.dynamic_tools.items():
            schemas.append(tool["schema"])
        return schemas
    
    def record_usage(self, name, success):
        """Track tool effectiveness for future selection."""
        if name in self.dynamic_tools:
            self.dynamic_tools[name]["usage_count"] += 1
            if success:
                self.dynamic_tools[name]["success_count"] += 1
            self._persist(name)
    
    def get_effectiveness_report(self):
        """Return success rates per tool for injection into agent context."""
        ...
```

### Tool Effectiveness Context

Before the agent selects tools, inject a summary of past tool effectiveness:

```
Tool effectiveness against this device type (Linux Gateway):
- brute_force_ssh: 5/5 successful (100%) — already known creds
- http_cmd_injection: 0/3 successful (0%) — port 80 always closed
- brute_force_telnet: 0/3 successful (0%) — port 23 always closed

Recommendation: Skip http_cmd_injection and brute_force_telnet for this device type.
Focus on post-exploitation or novel approaches.
```

### Agent-Created Tools Survive Restarts

When the agent calls `create_tool`, the code is saved to `toolkit/dynamic/` and registered in the database. On next startup, all persisted dynamic tools are loaded and made available:

```python
def _load_persisted_tools(self):
    """Load previously created dynamic tools from database."""
    rows = self.db.execute("SELECT * FROM dynamic_tools").fetchall()
    for row in rows:
        code_path = Path(row["code_path"])
        if code_path.exists():
            mod = load_dynamic_tool(code_path)
            if hasattr(mod, "run"):
                self.dynamic_tools[row["name"]] = {...}
```

### Schema Evolution

The `execute_exploit` enum should NOT be hardcoded. Instead, it should be dynamically built from the registry:

```python
def build_exploit_schema(registry):
    """Build execute_exploit schema with all available tool names."""
    tool_names = list(TOOLS.keys()) + list(registry.dynamic_tools.keys())
    schema = {
        "type": "function",
        "function": {
            "name": "execute_exploit",
            "parameters": {
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "enum": tool_names,
                    },
                    ...
                }
            }
        }
    }
    return schema
```

## Files to Modify

- `core/tool_registry.py` (new) — dynamic tool registry with persistence
- `core/tools/registry.py` — generate schemas dynamically instead of static list
- `core/tools/dispatcher.py` — use dynamic registry for tool resolution
- `core/agent.py` — pass dynamic schemas to LLM; record tool usage results
- Depends on: `01_persistent_memory.md`

## Estimated Effort

Medium. The registry is conceptually simple but touches many files. The main value is in the effectiveness tracking feedback loop.

## Implementation Notes

Executed. Files created:
- `core/tool_tracker.py` — `ToolTracker` class with `get_tool_stats()`, `rank_tools()`, `recommend_tools()` (with exploration bonus for untried tools), `build_tool_context()`. Uses memory store's tool_history table.
