GSIR Deterministic Core – Authority Contract

1. Only code inside /src may execute.
2. Only task_runner may modify /registry.
3. /registry is append-only.
4. No external network calls are allowed during execution.
5. All outputs must be reproducible from versioned inputs.
6. External LLM output is advisory only and must never directly modify state.
7. Every state mutation must produce:
   - input_hash
   - output_hash
   - git_commit
   - schema_version
   - UTC timestamp