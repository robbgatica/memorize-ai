# Multi-LLM Setup Guide

This guide explains how to use the Memory Forensics MCP Server with different LLMs (Large Language Models), including Claude, Llama (via Ollama), GPT-4, and others.

## Overview

The Memory Forensics MCP Server is **LLM-agnostic** - it communicates via the Model Context Protocol (MCP), which any compatible client can use. The server doesn't care which LLM you use; it just exposes memory forensics tools via a standard interface.

**What this means:**
- Same server code works with all LLMs
- Switch between LLMs by changing the client
- Use Claude for production, Llama for offline/confidential work
- Optimize tool descriptions per LLM capability

## Supported LLM Profiles

The server supports different LLM profiles that optimize tool descriptions:

| Profile | Use Case | Output Format | Description Length |
|---------|----------|---------------|-------------------|
| `claude` | Claude Opus/Sonnet | Markdown | Detailed (500 chars) |
| `llama70b` | Llama 3.1 70B+ | Markdown | Moderate (300 chars) |
| `llama13b` | Llama 13B or smaller | JSON | Concise (150 chars) |
| `gpt4` | GPT-4/GPT-4 Turbo | Markdown | Detailed (500 chars) |
| `minimal` | Any small model | JSON | Minimal (100 chars) |

Set the profile via environment variable:
```bash
export MCP_LLM_PROFILE=llama70b
python server.py
```

---

## Option 1: Claude (via Claude Code)

**Best for:** Production use, highest quality analysis

### Setup

1. **Install Claude Code:**
   ```bash
   # Download from https://claude.com/claude-code
   ```

2. **Configure MCP Server:**
   Edit `~/.claude/mcp.json`:
   ```json
   {
     "mcpServers": {
       "memory-forensics": {
         "command": "/home/robb/tools/memory-forensics-mcp/venv/bin/python",
         "args": ["/home/robb/tools/memory-forensics-mcp/server.py"]
       }
     }
   }
   ```

3. **Start Claude Code:**
   ```bash
   claude
   ```

4. **Use Tools:**
   ```
   You: "List available memory dumps"
   Claude: [calls list_dumps tool automatically]

   You: "Analyze Win11Dump for signs of compromise"
   Claude: [calls process_dump, detect_anomalies, generate_timeline, etc.]
   ```

### Profile Configuration

Claude uses the `claude` profile by default (detailed descriptions).

No additional configuration needed.

---

## Option 2: Llama (via Ollama) - Local/Offline

**Best for:** Confidential investigations, offline/local environments, cost savings

### Prerequisites

1. **Install Ollama:**
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Pull a Llama model:**
   ```bash
   # Recommended: Llama 3.1 70B (best quality)
   ollama pull llama3.1:70b

   # Or: Llama 3.2 (smaller, faster)
   ollama pull llama3.2:latest

   # Or: Llama 3.1 8B (minimal resources)
   ollama pull llama3.1:8b
   ```

3. **Start Ollama server:**
   ```bash
   ollama serve
   ```

### Setup Option A: Using Example Client (Recommended)

1. **Install client dependencies:**
   ```bash
   cd /home/robb/tools/memory-forensics-mcp/examples
   pip install -r requirements.txt
   ```

2. **Configure LLM profile:**
   ```bash
   # For Llama 3.1 70B or larger
   export MCP_LLM_PROFILE=llama70b

   # For Llama 13B-70B
   export MCP_LLM_PROFILE=llama13b

   # For Llama 8B or smaller
   export MCP_LLM_PROFILE=minimal
   ```

3. **Run the client:**
   ```bash
   python ollama_client.py
   ```

4. **Specify model (optional):**
   ```bash
   OLLAMA_MODEL=llama3.2:latest python ollama_client.py
   ```

### Setup Option B: Custom Integration

If you want to build your own MCP client:

1. **Install MCP Python SDK:**
   ```bash
   pip install mcp
   ```

2. **Create your client:**
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters

   async def main():
       server_params = StdioServerParameters(
           command="/path/to/venv/bin/python",
           args=["/path/to/server.py"]
       )

       async with ClientSession(server_params) as session:
           # Initialize
           await session.initialize()

           # List tools
           tools = await session.list_tools()

           # Call a tool
           result = await session.call_tool("list_dumps", {})
           print(result)

   asyncio.run(main())
   ```

3. **Integrate with Ollama:**
   - Send user prompt + tool descriptions to Ollama
   - Parse tool calls from Ollama response
   - Execute tools via MCP client
   - Return results to Ollama for analysis

See `examples/ollama_client.py` for a complete implementation.

### Performance Notes

**Model Recommendations:**
- **Llama 3.1 70B**: Best quality, comparable to Claude for most tasks
- **Llama 3.1 13B**: Good balance of speed/quality
- **Llama 3.2**: Faster, lighter, good for basic analysis
- **Llama 3.1 8B**: Minimal resources, basic capabilities

**Hardware Requirements:**
- 70B models: 48GB+ RAM or GPU
- 13B models: 16GB+ RAM
- 8B models: 8GB+ RAM

---

## Option 3: GPT-4 (via OpenAI API)

**Best for:** OpenAI ecosystem users

### Setup

1. **Install OpenAI SDK:**
   ```bash
   pip install openai mcp
   ```

2. **Set API key:**
   ```bash
   export OPENAI_API_KEY=sk-...
   ```

3. **Configure MCP server:**
   ```bash
   export MCP_LLM_PROFILE=gpt4
   ```

4. **Create client:**
   ```python
   import openai
   from mcp import ClientSession

   # Similar pattern to Ollama client
   # Replace Ollama API calls with OpenAI API calls
   ```

**Note:** No official OpenAI MCP client exists yet. You'll need to write a client similar to the Ollama example that:
- Connects to MCP server via stdio
- Sends prompts to OpenAI API
- Parses function calls
- Executes via MCP
- Returns results

---

## Option 4: Custom/Local LLMs

**Examples:** Mistral, Phi, CodeLlama, custom fine-tuned models

### Via Ollama

If your model is available in Ollama:

```bash
ollama pull mistral:latest
OLLAMA_MODEL=mistral:latest MCP_LLM_PROFILE=llama13b python examples/ollama_client.py
```

### Via Other Runtimes

If using llama.cpp, vLLM, or other runtimes:

1. **Start your LLM server** (with API endpoint)
2. **Modify `examples/ollama_client.py`:**
   - Change `ollama_url` to your server URL
   - Adjust API call format if needed
3. **Set appropriate profile:**
   ```bash
   export MCP_LLM_PROFILE=minimal  # for small models
   export MCP_LLM_PROFILE=llama70b # for large models
   ```

---

## Profile Configuration Reference

### Environment Variables

```bash
# Set LLM profile
export MCP_LLM_PROFILE=llama70b

# Override individual settings (optional)
export MCP_OUTPUT_FORMAT=json
export MCP_VERBOSITY=concise
```

### Profile Details

**Claude Profile** (`claude`):
- Markdown output with rich formatting
- Detailed 500-character tool descriptions
- Includes usage examples
- Optimized for Claude's context understanding

**Llama 70B Profile** (`llama70b`):
- Markdown output
- Moderate 300-character descriptions
- Includes examples
- Good for Llama 3.1 70B and similar large models

**Llama 13B Profile** (`llama13b`):
- JSON-preferred output for structured data
- Concise 150-character descriptions
- No examples (to save tokens)
- Good for Llama 13B-70B

**Minimal Profile** (`minimal`):
- JSON output only
- Minimal 100-character descriptions
- No examples
- For small models (7B-13B) or limited context

---

## Comparison: Claude vs Llama

| Aspect | Claude (via Claude Code) | Llama (via Ollama) |
|--------|--------------------------|-------------------|
| **Setup Complexity** | Easy (official client) | Moderate (custom client) |
| **Cost** | Paid API | Free (local) |
| **Quality** | Highest | Very good (70B) to moderate (8B) |
| **Speed** | Fast (cloud) | Varies (local hardware) |
| **Privacy** | Cloud-based | Fully local/offline |
| **Context Window** | 200K tokens | 128K tokens (Llama 3.1) |
| **Tool Calling** | Native support | Manual parsing needed |
| **Best For** | Production, highest quality | Confidential, offline environments |

---

## Workflow Examples

### Claude Code Workflow

```
$ claude

You: "Analyze Win11Dump memory dump"

Claude: Let me analyze that dump for you.
[automatically calls list_dumps]
[automatically calls process_dump Win11Dump]
[automatically calls detect_anomalies Win11Dump]

I found several suspicious indicators:
1. cmd.exe spawned by winword.exe (PID 2048) [CRITICAL]
   This indicates a possible macro exploit...

[automatically calls generate_timeline Win11Dump]
[automatically calls export_data Win11Dump html]

I've created a complete HTML report at: exports/Win11Dump_report_20241211.html
```

### Ollama Workflow

```bash
$ python examples/ollama_client.py

You: Analyze Win11Dump memory dump

[Calling tool: list_dumps]
[Calling tool: process_dump]
[Calling tool: detect_anomalies]

Assistant: Analysis complete\!

Found 3 critical anomalies:
- cmd.exe spawned by winword.exe (macro exploit)
- svch0st.exe process (typosquatting svchost.exe)
- Process running from AppData\Temp (unusual location)

Timeline shows:
1. Document opened at 14:22
2. cmd.exe spawned 30s later
3. Network connection to 192.168.1.100:4444

I recommend immediate incident response.
```

---

## Troubleshooting

### "Ollama not responding"

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve
```

### "MCP server connection failed"

1. **Check virtual environment:**
   ```bash
   ls /home/robb/tools/memory-forensics-mcp/venv/bin/python
   ```

2. **Test server directly:**
   ```bash
   cd /home/robb/tools/memory-forensics-mcp
   ./venv/bin/python server.py
   # Should wait for input (stdio mode)
   ```

3. **Check dependencies:**
   ```bash
   ./venv/bin/python -c "import mcp, aiosqlite, volatility3; print('OK')"
   ```

### "Tool calls not working with Ollama"

- Smaller models (8B, 13B) struggle with complex tool calling
- Try Llama 3.1 70B for best results
- Use `MCP_LLM_PROFILE=llama70b` for optimized descriptions

---

## Security Considerations

### Offline/Isolated Environments

For maximum security:
1. **Use Ollama** (fully local, no network calls)
2. **Disable network** on analysis machine if required
3. **Transfer dumps** via USB/physical media
4. **Export results** to JSON/CSV for offline review

### Data Privacy

| LLM Backend | Data Sent To | Recommendation |
|-------------|-------------|----------------|
| Claude (Cloud) | Anthropic servers | OK for non-confidential |
| Ollama (Local) | Localhost only | OK for confidential |
| GPT-4 (Cloud) | OpenAI servers | OK for non-confidential |

**For confidential/classified investigations:** Use Ollama exclusively.

---

## Performance Tuning

### For Ollama/Llama

**GPU Acceleration:**
```bash
# Ollama will automatically use CUDA if available
ollama run llama3.1:70b
```

**CPU-Only (slower):**
```bash
CUDA_VISIBLE_DEVICES="" ollama run llama3.1:8b
```

**Memory limits:**
```bash
# Limit to 16GB
ollama run llama3.1:13b --memory 16g
```

### For Claude Code

- No tuning needed (cloud-based)
- Response times depend on network latency

---

## Summary

**Quick Reference:**

| Use Case | Recommended Setup |
|----------|------------------|
| Production forensics | Claude Code (best quality) |
| Confidential investigations | Ollama + Llama 3.1 70B |
| Offline/local analysis | Ollama + Llama 3.1 70B |
| Resource-constrained | Ollama + Llama 3.2 |
| Cost-sensitive | Ollama + any Llama model |

**Getting Started:**
1. For Claude: Use this guide to set up Claude Code (easiest)
2. For Llama: Install Ollama, pull a model, run `python examples/ollama_client.py`
3. For other LLMs: Adapt the Ollama client example

The MCP server is the same for all - only the client changes\!
