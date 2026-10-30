"""
Mapping prompt for the second fusion round.

Purpose: after the dedup verdict has been frozen, run one purely descriptive
round that annotates each discarded specification with the retained
specification it approximates, producing fusion_groups.json.

Design boundaries:
- This module provides only the additional user message. Both rounds share the
  same `FUSION_DEDUP_SYSTEM_PROMPT` (unchanged conversation prefix, so the prefix
  cache is reused and round 1 behavior stays attributable). The two fusion
  constants in `result_extract_prompt.py` must not be modified.
- This round has no write access to the surviving set: the caller
  (`analysis_agent/fusion.py`) computes the kept list before starting it; the
  kept list is element-wise identical whether this round succeeds, fails, or
  times out.
- The prompt schema mirrors the round-1 rules: every discarded spec_id is
  assigned to exactly one group or to `unmapped`; kept_spec_id must be a real
  retained id; roles never pair across.
"""

# ---------------------------------------------------------------- Round 2 user template

FUSION_MAPPING_USER_PROMPT_TEMPLATE = """========================================
[Additional task: annotate each already-decided duplicate with the retained specification it approximates]
========================================
In your previous answer you decided that the spec_ids listed below are duplicates to discard.
That verdict is **frozen**. This round is **annotation only, no judgment** -- you must not add, revoke or modify any
discard decision, and you must not change any conclusion from your previous answer because of this round's annotation.

[Discarded items to annotate (round-1 verdict, frozen)]
{discarded_digest_json}

For each discarded item above, name the **retained** specification it **approximates**.
Retained specifications are those you did **not** list in discarded_spec_ids in your previous answer; their digest is in
[Global specification digest (with origin_direction)] above.

[Annotation discipline]
6. Every discarded spec_id must fall into exactly one group, or be listed in `unmapped`.
   -- If no retained peer of the same role is close enough, put it in `unmapped`; **do not invent** a kept_spec_id.
   Note: this is **not** a new judgment -- keep/discard conclusions are exactly those in your previous answer;
   this round only writes out the conclusions you already made.
7. Only specifications that genuinely needed discarding appear in groups; a specification with no close peer is not a group element.
8. A spec_id appears in at most one group's discarded_spec_id_list; kept_spec_id must be a real spec_id
   from the digest above and must not appear in any discarded_spec_id_list;
   roles within a group must match (roles are **never** paired across); each group has at least one discarded specification.

========================================
[Output format and data-structure dictionary (strictly follow)]
========================================
You must output exactly one valid JSON object.

JSON structure and field requirements:
{{
  "groups": [
    {{
      "discarded_spec_id_list": ["string"],  // discarded duplicate spec_ids in this group (excluding kept_spec_id)
      "kept_spec_id": "string",               // retained spec_id that the discarded items closely approximate
      "spec_desc": "string"                   // the matching intent these specs share (one sentence), explaining the dedup basis
    }}
  ],
  "unmapped": ["string"]                      // spec_ids already decided as discarded but with no close retained peer of the same role
}}

Field semantics (consistent with the discipline above):
- Add a group element only when duplication genuinely requires discarding; non-duplicate specifications do not appear in the output and are retained by default.
- Every discarded spec_id appears in at most one group; kept_spec_id must come from the input and must not appear in any
  discarded_spec_id_list; each group has at least one discarded specification.
- Keep/discard results must exactly match the judgment you already made -- this field only writes out that conclusion.

[Complete JSON output examples]
Example 1: no discarded items to annotate (most common)
{{
  "groups": [],
  "unmapped": []
}}

Example 2: one duplicate group (d01_sink_01 and d02_sink_02 both approximate d03_sink_03)
{{
  "groups": [
    {{
      "discarded_spec_id_list": ["d01_sink_01", "d02_sink_02"],
      "kept_spec_id": "d03_sink_03",
      "spec_desc": "These specifications all describe a classic execute sink"
    }}
  ],
  "unmapped": []
}}

Example 3: one discarded item has no peer, so it goes to unmapped
{{
  "groups": [],
  "unmapped": ["d04_flow_step_02"]
}}

Final instruction: output the valid JSON object directly (starting with {{ and ending with }}), with no Markdown markers or explanatory text.
"""
