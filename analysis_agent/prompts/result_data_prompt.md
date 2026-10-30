[Output format and data-structure dictionary (strictly follow)]

### 1. Output format

Your output must be a JSON object containing a `specifications` field. `specifications` is an array; each element is a specification object whose concrete structure is determined by its `role` field.

If the current execution result contains no valuable specification, return {"specifications": []}.

Output skeleton:
{
  "specifications": [
    { "role": "source", "description": "...", ... },
    { "role": "summary", "description": "...", ... }
  ]
}

#### (1) Basic component object

GroundTruthExample

- `source_code_result_id` (string, required/nullable): [Provenance anchor] the `id` in the upstream evidence pool (Code Results) that this example copies from (e.g. `"prev_cr_001"`). Required when `is_from_project=True`, and it must be an id that actually exists in the evidence pool; use `null` for synthetic examples with `is_from_project=False`.
  The system uses it to check the example against the referenced entry (id exists + file_path matches + code_snippet is a subset of the entry). **It is not an optional remark**: a wrong or missing value fails validation and wastes a generation attempt.

- `code_snippet` (array of strings, required): key code lines or blocks ordered as they appear in the source. Note: this is an array of strings, not one string. Extract only the most distinctive core statements (method signatures, key assignments, dangerous operations); ignore long unrelated logic, log statements and boilerplate.

  ⚠️ Subset rule (paired with `source_code_result_id`): when `is_from_project=True`, the content here must be a [subset of the referenced entry's `code_snippet`]. Removing unrelated middle lines is allowed, but **never rewrite, concatenate, complete, or introduce lines that are not in the referenced entry**.

  ⚠️ Contiguity/merge rule (extremely important):
  - Every element in the list must be one [contiguous code block] (join multi-line code with \n into a single string).
  - Lines that are physically adjacent in the original file [must] be merged into the same string element; never split them across elements.
  - Only when you removed unrelated/boilerplate lines and thereby physically broke the code may the lower part become the next element.

  ❌ Wrong (fragmented): ["class classA {", "  private final String fieldB;", "  void methodC(Object parameterD) {"]
  ✅ Correct (contiguous blocks): ["class classA {\n  private final String fieldB;\n  private final String fieldC;", "  void methodC(Object parameterC) {\n    this.fieldC = parameterC.toString();\n  }"]

- `is_from_project` (boolean, required): whether the example comes from the target project's real source (**source only**, unrelated to whether it participates in validation). If False (synthetic code), `purpose` must be "illustration" and `source_code_result_id` must be null.
- `file_path` (string, optional): relative path in the real source. Use null when `is_from_project` is false; when true it must exactly match the referenced entry's `file_path`.
- `purpose` (string, required): enum, one of ["validation", "illustration"].
  - "validation": a real Ground Truth -- the example's semantic side (declaration/definition side vs call/access side) matches the side the specification matches, and it comes from the target project; its file_path is used downstream for GT hit validation.
  - "illustration": supporting material -- only helps explain the target semantics (e.g. a method declaration/definition when the specification matches the call side, third-party source, synthetic example); it does **not** participate in GT hit validation.
  Decision basis (extremely important): first decide which side the specification matches --
  · declaration-side match: parameter / return_value patterns (mark validation when the example is declaration/definition code);
  · access/call-side match: argument / receiver / field patterns, plus summary / flow_step. For field, prefer the read/write site (mark validation); if only the field declaration is given, mark illustration.
- `explanation` (string, required): natural-language explanation of which variable/call in this code corresponds to the specification.

#### (2) Node pattern objects (flat design)

All pattern objects are distinguished by `pattern_type`. Each pattern object contains only `pattern_type` and `matching_description` (except CustomLogicPattern); no nesting is used.

[matching_description specification (extremely important)]

Because there is no nested ClassPattern / MethodPattern structure, `matching_description` must cover all three levels -- class -> method -> node -- in one natural-language sentence.

Recommended phrasing:
- Node-level patterns (parameter / argument / field / return_value / receiver):
  "in [class description], the [node description] of the [method description]"
- Method-level match (summary's matching_description):
  "in [class description], the [method description]"

[Class description requirements]:
- Fully qualified names first: when a fully qualified class name is available, always provide it (e.g. `com.example.controller.UserController`); it greatly improves CodeQL match precision and eliminates same-name ambiguity.
- Inheritance/implementation: state explicitly whether indirect inheritance is included.
  Examples:
  - "extends `com.example.base.BaseService` (including indirect inheritance)"
  - "directly extends `com.example.base.BaseController`"
  - "implements the `org.springframework.web.servlet.HandlerInterceptor` interface"
- Global matching: if no specific class or method needs to be constrained, write "regardless of class" or "global match" in the description; the downstream CodeQL Agent understands this and skips the corresponding level.

Pattern types:

- ParameterPattern: matches a method declaration-side formal parameter
  - `pattern_type` (string, required): fixed to `"parameter"`
  - `matching_description` (string, required): full description covering class, method and parameter.
    Example: "in `com.example.controller.FileController` (annotated with @RestController), the first parameter (type String, annotated with @PathVariable) of method `getFile` annotated with @GetMapping"

- ArgumentPattern: matches a method call-site argument
  - `pattern_type` (string, required): fixed to `"argument"`
  - `matching_description` (string, required): full description covering class, method and argument.
    Example: "regardless of class, the first argument of every call to a method named `evaluate`"

- FieldPattern: matches a class field
  - `pattern_type` (string, required): fixed to `"field"`
  - `matching_description` (string, required): full description covering class and field.
    Example: "in class `com.example.model.UserContext`, the String field named `userInput`"

- ReturnValuePattern: matches a method return value
  - `pattern_type` (string, required): fixed to `"return_value"`
  - `matching_description` (string, required): full description covering class and method (the return value itself usually needs no extra description).
    Example: "in class `com.example.util.MarkupEncoder`, the return value of the public method named `encode`"

- ReceiverPattern: matches the call-site receiver (this/object state)
  - `pattern_type` (string, required): fixed to `"receiver"`
  - `matching_description` (string, required): full description covering class and method.
    Example: "in class `com.example.util.StringBuilder`, the receiver object of calls to method `append`"

- CustomLogicPattern: custom/fallback pattern
  - `pattern_type` (string, required): fixed to `"custom_logic"`
  - `matching_intent` (string, required): matching logic in plain natural language.
  - `codeql_generation_hint` (string, required): AST/DFG traversal hint for the CodeQL Agent.
  - `builtin_codeql_rule` (string, optional): a CodeQL built-in rule to reuse directly (e.g. `"path-injection"`).

#### (3) Top-level specification object (distinguished by `role`)

Every specification object has these common required fields:
- `description` (string): business/security meaning.
- `security_reason` (string): basis for the security judgment.
- `ground_truth_examples` (array of GroundTruthExample, required): length must be 1 to 5.

Depending on `role`, additional fields are required:

a. role = "source" or "sink"
- `node_pattern` (object, required): one of ParameterPattern, ArgumentPattern, FieldPattern, ReturnValuePattern, ReceiverPattern, CustomLogicPattern.

b. role = "summary"
- `matching_description` (string, required): natural-language description of the target method's full matching characteristics (class and method levels).
- `mapping_type` (string, required): enum, one of ["arg_to_return", "this_to_return", "arg_to_this", "this_to_arg"].
- `source_arg_index` (integer, optional): required when `mapping_type` is `arg_to_return` or `arg_to_this`; index (0-based) of the taint-inflow parameter.
- `target_arg_index` (integer, optional): required when `mapping_type` is `this_to_arg`; index (0-based) of the taint-outflow parameter.
- ⚠️ `mapping_type` must be derived from **evidence**, never guessed from the method name or intuition: first find the call site in the upstream evidence,
  observe where the tainted data actually goes (which argument it enters from -> whether it leaves through the return value / is written into this / which out-parameter it is written into), then pick the enum value.
  If the evidence does not establish the flow, omit the summary rather than filling in an assumed `mapping_type`.
- ⚠️ A summary means only [taint passes through this method]; it says nothing about [whether the method is safe / blocks taint]. Never treat a method as a sanitization point just because its name contains
  sanitize / validate / escape / normalize; on the contrary, such methods are typical summary candidates.

c. role = "flow_step"
- `pattern` (CustomLogicPattern object, required): must use CustomLogicPattern to describe complex non-method-level propagation.

### 2. Key constraints and pitfalls (must follow)

a. matching_description must cover every level: since there is no nested ClassPattern / MethodPattern, describe class, method and node (or class and method) together in matching_description. Never write only the node and omit class/method information.

b. Class matching prefers fully qualified names and explicit inheritance: whenever the package name can be inferred from context, use the fully qualified name. When describing inheritance/implementation, state whether it is "direct inheritance" or "including indirect inheritance", so the CodeQL Agent can choose between getASourceSupertype() and getASourceSupertype*().

c. code_snippet must be an array and follow the contiguity/merge rule: it must be an array of strings, never one long string. Physically adjacent lines must be merged into a single element.

d. OR logic: this structure has no nested OR tree. If a Source may be A or B, output two separate Specification objects in the JSON array.

e. Use global-match semantics when appropriate: if the rule does not need to constrain a specific class or method, write "regardless of class" or "global match" in matching_description. Never invent class or method names just to fill in information.

f. purpose discipline: never mark a declaration-side example as validation just to make it "validatable" (downstream GT validation then no-ops and wastes retry budget), and never mark the project's real code on the actual matching side as illustration (losing a valid validation anchor).

g. Provenance-anchor discipline: an example with `is_from_project=True` must give `source_code_result_id` that really exists in the evidence pool; its `file_path` must match the referenced entry and its `code_snippet` must be a subset. The system checks "id existence / path consistency / subset relation" one by one; any failure fails the generation attempt and consumes a generation opportunity. Note: **faithfulness to the referenced entry** outranks "looking good" -- copy fewer lines rather than completing or rewriting them yourself.

h. A summary's mapping_type needs flow evidence: a wrong `mapping_type` creates a taint edge in the wrong direction, which downstream can hardly detect automatically and which silently pollutes recall. Read the call site first, then pick the enum value; if the evidence is insufficient, do not report it.

### 3. Complete JSON output example

{
  "specifications": [
    {
      "role": "source",
      "description": "Variable receiving a URL path parameter in a Spring Boot controller",
      "security_reason": "URL path parameters are directly user-controlled; passing one into a file operation without filtering causes path traversal.",
      "ground_truth_examples": [
        {
          "code_snippet": [
            "@GetMapping(\"/files/{filename}\")\npublic ResponseEntity<byte[]> getFile(@PathVariable String filename) {",
            "    File file = new File(BASE_DIR, filename);"
          ],
          "is_from_project": true,
          "file_path": "src/main/java/com/example/controller/FileController.java",
          "source_code_result_id": "prev_cr_001",
          "purpose": "validation",
          "explanation": "The parameter filename on line 2 is the Source because it is annotated with @PathVariable."
        }
      ],
      "node_pattern": {
        "pattern_type": "parameter",
        "matching_description": "in classes whose fully qualified name ends with `com.example.controller` and that are annotated with @RestController or @Controller, the parameter annotated with @PathVariable of methods annotated with routing annotations such as @GetMapping or @PostMapping"
      }
    },
    {
      "role": "sink",
      "description": "Return value of a markup encoder library's encode method as an implicit Sink",
      "security_reason": "The library's encode method does not fully escape certain character sequences, so malicious data leaves the project boundary through the API return value and indirectly triggers injection-class vulnerabilities.",
      "ground_truth_examples": [
        {
          "code_snippet": [
            "public String encode(String text) {",
            "    // ... encoding logic is flawed ...",
            "    return result;",
            "}"
          ],
          "is_from_project": true,
          "file_path": "src/main/java/com/example/MarkupEncoder.java",
          "source_code_result_id": "prev_cr_002",
          "purpose": "validation",
          "explanation": "The return value of encode is an implicit Sink; tainted data leaves through the return value without sufficient sanitization."
        }
      ],
      "node_pattern": {
        "pattern_type": "return_value",
        "matching_description": "in class `com.example.MarkupEncoder`, the return value of the public method named `encode`"
      }
    },
    {
      "role": "summary",
      "description": "Taint passthrough rule for a custom data processor",
      "security_reason": "All data-processing classes in the project extend AbstractProcessor; its process method passes the input parameter straight to the return value without sanitization.",
      "ground_truth_examples": [
        {
          "code_snippet": [
            "public class UserParser extends AbstractProcessor<User> {",
            "    @Override\n    public String process(User input) {",
            "        return input.getName();\n    }",
            "}"
          ],
          "is_from_project": true,
          "file_path": "src/main/java/com/example/parser/UserParser.java",
          "source_code_result_id": "prev_cr_003",
          "purpose": "illustration",
          "explanation": "UserParser extends AbstractProcessor; parameter input (index 0) of its process method is used directly in the return statement."
        }
      ],
      "matching_description": "in classes that extend `com.example.base.AbstractProcessor` (including indirect inheritance), the method named `process`",
      "mapping_type": "arg_to_return",
      "source_arg_index": 0
    },
    {
      "role": "flow_step",
      "description": "Taint carried through a global ThreadLocal cache",
      "security_reason": "The project stores user context in a ThreadLocal; tainted data stored there is retrieved in any downstream method, bypassing normal parameter passing.",
      "ground_truth_examples": [
        {
          "code_snippet": [
            "UserContext.set(\"userInput\", taintedData);",
            "// ... across several method calls ...",
            "String data = (String) UserContext.get(\"userInput\");"
          ],
          "is_from_project": false,
          "file_path": null,
          "source_code_result_id": null,
          "purpose": "illustration",
          "explanation": "Line 1 stores into the global context and line 3 retrieves it, forming cross-method implicit propagation."
        }
      ],
      "pattern": {
        "pattern_type": "custom_logic",
        "matching_intent": "Match calls to UserContext.set (store) and calls to UserContext.get (retrieve).",
        "codeql_generation_hint": "In CodeQL, define isAdditionalTaintStep to connect the argument node of UserContext.set with the return-value node of UserContext.get.",
        "builtin_codeql_rule": null
      }
    }
  ]
}
