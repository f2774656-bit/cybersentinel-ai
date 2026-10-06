# AI Analyst

Workers AI is an analyst layer, not a scoring authority.

Input is a structured object containing target and evidence-backed findings. The prompt requires the model to separate EVIDENCE, INFERENCE and RECOMMENDATION and to state uncertainty when evidence is insufficient.

The provider is abstracted behind `AIProvider`, allowing a future second provider without coupling scanner logic to an LLM vendor.

Default model is configurable through `CLOUDFLARE_AI_MODEL`; model names are not treated as permanent platform guarantees.
