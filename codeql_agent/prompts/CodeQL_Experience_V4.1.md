# CodeQL Scripting Experience Summary (v4.1)

> **Preface**: CodeQL is a low-level static-analysis query language, and high-quality training material is relatively scarce, so LLMs tend to hallucinate around type casts, generics, and declaration-side versus call-side distinctions. This document collects accurate CodeQL rule-editing patterns and common pitfalls.

---

## I. Common matching patterns

### 1.1 Class matching strategy for methods (overview)

Most CodeQL matching rules revolve around methods, and the first decision is: **how to determine the class that owns the method?** For call-side nodes (Argument, Receiver, Summary), three strategies are available:

**Strategy A (recommended default): `getCallee().getDeclaringType()`**
- **Meaning**: match the class where the method is declared/defined (the "definer's view").
- **Use when**: most scenarios, especially static methods and exact API matching for JDK/framework classes.
- **Example**: match `Runtime.getRuntime().exec(cmd)` -> match `java.lang.Runtime`.
- **Reason**: static methods have no object instance; `getQualifier()` returns a type access rather than an object reference and cannot serve as a valid type basis.

**Strategy B (polymorphism/inheritance): `getCallee().getDeclaringType().getASourceSupertype*()`**
- **Meaning**: match the declaring class and all its ancestors (including interfaces) via the transitive closure.
- **Use when**: the target method is defined in an interface or abstract class and all implementations/overrides must match.
- **Example**: match every call to an implementation of `CacheNotifyService.cache()`.

**Strategy C (caller's view): `getQualifier().getType()`**
- **Meaning**: match the static type of the receiver expression at the call site (the "caller's view").
- **Use when**: you need "a call to this method on an object of a specific type" rather than caring where the method is defined.
- **Limitation**: does not work for static methods (no object instance).
- **Example**: match every `append()` called on a `StringBuilder` instance.

**Decision tree:**
1. Is the target method static? -> **must use strategy A** (no Qualifier instance).
2. Is the target method defined in an interface/abstract class and must all implementations match? -> **use strategy B**.
3. Must the caller's concrete type be constrained (rather than the method definition site)? -> **use strategy C**.
4. Otherwise -> **use strategy A by default**.

**Core difference between strategy A and strategy C (inheritance/polymorphism):**

```java
// Parent class defines the method
public class Animal {
    public void speak() { ... }
}
// Child class overrides the method
public class Dog extends Animal {
    @Override
    public void speak() { ... }
}
// Call site
Animal a = new Dog();
a.speak();
```

| API | Return value | Meaning |
| :--- | :--- | :--- |
| `c.getQualifier().getType()` | `Animal` | the **static reference type** of `a` in the code |
| `c.getCallee().getDeclaringType()` | `Animal` | `speak()` is originally **declared** in `Animal` |

If the code is changed to `Dog d = new Dog(); d.speak();`:

| API | Return value | Meaning |
| :--- | :--- | :--- |
| `c.getQualifier().getType()` | `Dog` | the **static reference type** of `d` in the code |
| `c.getCallee().getDeclaringType()` | `Dog` or `Animal` | depends on whether CodeQL resolves the override or the original declaration |

**IMPORTANT: void methods and data-flow nodes:**

In CodeQL's data-flow model, **only expressions that produce a value are data-flow nodes**. A call to a `void` method produces no value, so `node.asExpr() = c` is **always false** for a void method call (the call has no node in the data-flow graph).

```
// For the void method rb.addHeader(name, value):
rb.addHeader(name, value)
│        │       │    │
│        │       │    └── value -> yes, a data-flow node (the argument carries a value)
│        │       └────── name  -> yes, a data-flow node
│        └────────────── addHeader -> the method itself, not a node
└─────────────────────── rb -> yes, a data-flow node (the object reference is a value)

The whole call rb.addHeader(name, value) -> no, not a data-flow node (void, produces no value)
```

Therefore, to match nodes related to a `void` method call, bind to its **arguments** or **qualifier**, not to the call expression itself:
- `node.asExpr() = c.getArgument(i)` -> valid
- `node.asExpr() = c.getQualifier()` -> valid
- `node.asExpr() = c` -> not valid for void methods

To match **all** method calls regardless of return type, match at the `Call` level without wrapping a `DataFlow::Node`:
```ql
from Call c
where c.getCallee().getDeclaringType().hasName("RequestBuilder")
select c
```

---

### 1.2 Method matching rules

This section shows the dimensions of method matching. Since the end goal is always to bind a method to a data-flow node, the examples use different node kinds (Parameter, Argument, ReturnStmt, Receiver); **focus on the method matching conditions themselves**; node binding is covered in Chapter II.

The two core classes for methods in CodeQL are the declaration-side `Callable` (subclasses include `Method` and `Constructor`) and the call-side `Call` (subclasses include `MethodCall` and `ConstructorCall`).

**Matching the method name and owning class:**

The following example uses a declaration-side parameter node and shows the most basic method matching logic:
```ql
predicate isParameterNode(DataFlow::Node node) {
    exists(Parameter p |
        node.asParameter() = p and
        // 1. Match the method name (getCallable returns Callable)
        p.getCallable().getName() = "methodName" and
        // 2. Match the fully qualified name of the owning class
        // RULE: always use .getSourceDeclaration() to locate the actually declaring class, to avoid generics/proxy classes
        p.getCallable().getDeclaringType().getSourceDeclaration()
            .hasQualifiedName("com.package.name", "ClassName") and
        // 3. Match the parameter position
        p.getPosition() = 0
    )
}
```

> **Note**: for inner classes, the fully qualified name matches as `.hasQualifiedName("com.package.name", "OuterClass$InnerClass")`.

**Matching inheritance relationships:**

The following example uses a call-side argument node and shows how to match the owning class through inheritance:
```ql
predicate isArgumentNode(DataFlow::Node node) {
    exists(Call c |
        // 1. Constrain the called method name
        c.getCallee().hasName("methodName") and
        // 2. Constrain a supertype of the owning class
        // RULE: use * to walk all ancestor classes/interfaces and avoid misses
        c.getCallee().getDeclaringType().getSourceDeclaration().getASourceSupertype*()
            .hasQualifiedName("com.package.name", "ParentClassName") and
        // 3. Bind the input argument
        node.asExpr() = c.getArgument(0)
    )
}
```

**Matching annotations:**

The following example uses a declaration-side return node (`ReturnStmt`) and shows annotation-based method matching:
```ql
predicate isReturnNode(DataFlow::Node node) {
    exists(ReturnStmt ret, Callable m |
        // 1. Match a class annotation
        // NOTE: Java annotations do not support generics or bridges, so annotation types need no .getSourceDeclaration()
        m.getDeclaringType().getSourceDeclaration().getAnAnnotation().getType().(RefType)
            .hasQualifiedName("org.springframework.boot.jackson", "JsonComponent") and
        // 2. Match method annotations (multiple annotations present)
        m.getAnAnnotation().getType().hasName("Override") and
        m.getAnAnnotation().getType().hasName("Transactional") and
        // 3. Bind the method and the return node
        m = ret.getEnclosingCallable().getSourceDeclaration() and
        node.asExpr() = ret.getExpr()
    )
}
```

**Matching method signatures:**

For extreme cases such as overloads, distinguish methods by signature. The following example uses a call node (Receiver):
```ql
predicate isReceiverNode(DataFlow::Node node) {
    exists(Call c |
        // 1. Match the method name
        c.getCallee().getName() = "methodName" and
        // 2. Match the fully qualified name of the owning class
        c.getCallee().getDeclaringType().getSourceDeclaration()
            .hasQualifiedName("com.package.name", "ClassName") and
        // 3. Match the signature
        // 3.1 Match the parameter count
        c.getCallee().getSourceDeclaration().getNumberOfParameters() = 2 and
        // 3.2 Match parameter type signatures (reference types and primitives are handled differently)
        // a. Reference type (e.g. String) -> cast to RefType
        c.getCallee().getSourceDeclaration().getParameterType(0).(RefType)
            .hasQualifiedName("java.lang", "String") and
        // b. Primitive type (e.g. int) -> no cast needed; use hasName
        c.getCallee().getSourceDeclaration().getParameterType(1).hasName("int") and
        // c. Array/varargs (e.g. Object[]) -> cast to Array first, then get the component type
        // RULE: the array type is named Array (it used to be ArrayType):
        //       writing .(ArrayType) fails to compile; do not revert to the old name.
        c.getCallee().getSourceDeclaration().getParameterType(2).(Array)
            .getComponentType().(RefType).hasQualifiedName("java.lang", "Object") and
        // d. Generic variable (e.g. T, E) -> never cast to RefType; test with instanceof
        (c.getCallee().getSourceDeclaration().getParameterType(3) instanceof TypeVariable) and
        // 4. Bind the data-flow node to the call node
        node.asExpr() = c
    )
}
```

> **Note**: parameter type matching is complex and error-prone; unless overloads really must be distinguished, prefer not to use it.

**Matching constructors:**

`Callable` can represent both `Method` and `Constructor`; likewise `Call` represents both `MethodCall` and `ConstructorCall`. A constructor's name equals its class name, so constructor matching follows the same logic as regular method matching:
```ql
predicate isConstructorCallNode(DataFlow::Node node) {
    exists(Call c |
        // 1. The constructor name equals the class name
        c.getCallee().getName() = "ClassName" and
        // 2. Match the fully qualified name of the owning class
        c.getCallee().getDeclaringType().getSourceDeclaration()
            .hasQualifiedName("com.package.name", "ClassName") and
        // 3. Bind the data-flow node (a constructor call yields the instantiated object)
        node.asExpr() = c
    )
}
```

**Matching static method calls:**

Static methods have no object instance, so strategy A is mandatory and `getQualifier()` cannot be used for type matching:
```ql
predicate isStaticCallArgument(DataFlow::Node node) {
    exists(Call c, Method callee |
        callee = c.getCallee().getSourceDeclaration() and
        // 1. Match the static method name
        callee.hasName("parseObject") and
        // 2. Match the owning class (strategy A, the only correct choice for static methods)
        callee.getDeclaringType().getSourceDeclaration()
            .hasQualifiedName("com.package.name", "JSONUtils") and
        // 3. Confirm it is static (optional; avoids interference from instance methods with the same name)
        callee.isStatic() and
        // 4. Bind the node
        node.asExpr() = c.getArgument(0)
    )
}
```

---

## II. Common node matching patterns

This chapter covers the most basic Source and Sink node matching in taint analysis. Core principle: prefer matching on the **declaration side** to avoid generic erasure and bridge-method interference.

> **Note**: each section focuses on **node binding logic** (how to bind the matched method to `DataFlow::Node`). The method conditions in the examples are simplified; for complex method matching (annotations, signatures, inheritance), see section 1.2 in Chapter I.

### 2.1 Declaration-side parameters (Parameter)

A method's declaration-side parameter is the most common Source matching pattern.

**Basic template:**
```ql
predicate isParameter(DataFlow::Node node) {
    exists(Parameter p |
        node.asParameter() = p and
        // 1. Match the method name
        p.getCallable().getName() = "methodName" and
        // 2. Match the fully qualified name of the owning class
        // RULE: always use .getSourceDeclaration() to locate the actually declaring class, to avoid generics/proxy classes
        p.getCallable().getDeclaringType().getSourceDeclaration().hasQualifiedName("com.package.name", "ClassName") and
        // 3. Match the parameter position
        // RULE: prefer the parameter position over the parameter name, which may be renamed by an override
        p.getPosition() = 0
    )
}
```

To match by parameter name, use `p.getName() = "parameterName"`, but overrides may rename parameters, so prefer the position.

**Matching through inheritance:**

When the target class is unknown but is known to extend a specific base class/interface, use `.getASourceSupertype*()` (the star means transitive closure over all indirect inheritance).
```ql
predicate isParameter(DataFlow::Node node) {
    exists(Parameter p |
        node.asParameter() = p and
        p.getCallable().getName() = "methodName" and
        // RULE: use * to walk all ancestor classes/interfaces and avoid misses
        p.getCallable().getDeclaringType().getSourceDeclaration().getASourceSupertype*()
            .hasQualifiedName("org.package.name", "ClassName") and
        p.getPosition() = 0
    )
}
```

**Matching through annotations:**

The following example shows class, method, and parameter annotation matching (see section 1.2 for more method dimensions):
```ql
predicate isParameter(DataFlow::Node node) {
    exists(Parameter p |
        node.asParameter() = p and
        // 1. Match a class annotation
        // NOTE: Java annotations do not support generics or bridges, so annotation types need no .getSourceDeclaration()
        p.getCallable().getDeclaringType().getSourceDeclaration().getAnAnnotation().getType().(RefType)
            .hasQualifiedName("org.springframework.boot.jackson", "JsonComponent") and
        // 2. Match a method annotation (by name only)
        p.getCallable().getSourceDeclaration().getAnAnnotation().getType().hasName("Override") and
        // 3. Match a parameter annotation and the parameter type
        p.getAnAnnotation().getType().hasName("RequestParam") and
        p.getType().(RefType).hasQualifiedName("java.lang", "String")
    )
}
```

### 2.2 Call-side arguments (Argument)

A call-side argument is another common Sink matching pattern. The key difference is that the entry point moves from the parameter definition to the call site.

**Default template (strategy A: match the class where the method is defined; see section 1.1 in Chapter I):**
```ql
predicate isArgument(DataFlow::Node node) {
     exists(Call mc |
         // 1. Constrain the called method name
         mc.getCallee().hasName("apply") and
         // 2. Constrain the owning class (strategy A: match the class where the method is declared/defined)
         // RULE: getCallee().getDeclaringType() matches "where the method is defined",
         // suitable for most scenarios, especially static methods and JDK/framework APIs
         mc.getCallee().getDeclaringType().getSourceDeclaration()
             .hasQualifiedName("com.package.name", "ClassName") and
         // 3. Constrain the input argument
         (
             // a. Match the object the method is called on, i.e. this (Qualifier)
             node.asExpr() = mc.getQualifier() or
             // b. Match the i-th argument of the call
             node.asExpr() = mc.getArgument(0) 
         )
     )
 }
```

**Alternative template with strategy C (match the caller's type; see section 1.1):**

When you need "a call to this method on an object of a specific type", use `getQualifier().getType()`. Note that this does not work for static methods.
```ql
predicate isArgument_StrategyC(DataFlow::Node node) {
    exists(Call mc |
        mc.getCallee().hasName("apply") and
        // Strategy C: match the static type of the qualifier
        // NOTE: instance methods only; does not work for static methods
        (
            // a. Match the class name directly
            mc.getQualifier().getType().hasName("ClassName") or
            // b. Match the fully qualified name
            mc.getQualifier().getType().(RefType).getSourceDeclaration()
                .hasQualifiedName("com.package.name", "ClassName")
        ) and
        node.asExpr() = mc.getArgument(0)
    )
}
```

There are two core differences between declaration-side parameters and call-side arguments: first, the entry point (parameter definition vs call site); second, the role of `node` (a `DataFlow::Node` bound to a `Parameter` entity vs to an argument expression). The method matching logic is the same and is not repeated here.

### 2.3 Declaration-side Return nodes

A method's return-value node can serve as a Sink in some scenarios (e.g. a public API returning sensitive information).

**Basic template:**
```ql
predicate isReturnNode(DataFlow::Node node) {
    exists(ReturnStmt ret, Method m |
        // 1. Bind the method (m) and the return node (ret)
        m = ret.getEnclosingCallable().getSourceDeclaration() and
        // 2. Match the method containing the return node
        m.hasQualifiedName("org.package.name", "ClassName", "methodName") and
        // 3. Bind DataFlow::Node to the returned expression
        node.asExpr() = ret.getExpr()
    )
}
```

For more complex method conditions (annotations, parameter signatures, etc.), see the "annotation matching" and "method signature matching" examples in section 1.2.

### 2.4 Method call nodes (Receiver)

A method call node (the call expression itself) can be either a Source or a Sink. The logic is similar to section 2.2, except that no argument position is specified: bind the call node itself.

**IMPORTANT PRECONDITION**: `node.asExpr() = mc` requires the call expression to be a data-flow node, i.e. the method **must return a value**. For a `void` method the call expression is not a data-flow node and the binding silently fails (see the "void methods and data-flow nodes" note in section 1.1).

**Default template (strategy A):**
```ql
predicate isReceiverNode(DataFlow::Node node) {
    exists(Call mc |
        // 1. Constrain the called method name
        mc.getCallee().hasName("methodName") and
        // 2. Constrain the owning class (strategy A: match the class where the method is declared/defined)
        mc.getCallee().getDeclaringType().getSourceDeclaration()
            .hasQualifiedName("com.package.name", "ClassName") and
        // 3. Bind DataFlow::Node to the MethodCall expression itself
        // WARNING: only valid for methods that return a value; a void call is not a data-flow node
        node.asExpr() = mc 
    )
}
```

**Alternative template with strategy C (match the caller's type):**
```ql
predicate isReceiverNode_StrategyC(DataFlow::Node node) {
    exists(Call mc |
        mc.getCallee().hasName("methodName") and
        // Strategy C: match the static type of the qualifier
        // NOTE: instance methods only; does not work for static methods
        mc.getQualifier().getType().hasName("QualifierType") and
        node.asExpr() = mc 
    )
}
```

### 2.5 Class field nodes (Field Access)

Class field nodes can serve as either Source or Sink. A simple template:
```ql
predicate isFieldNode_1(DataFlow::Node node) {
    exists(Field f |
      // Match the owning class name and the field name directly
      f.hasQualifiedName("org.package.name", "ClassName", "fieldName") and
      node.asExpr() = f.getAnAccess()
    )
}
```

The core is locating the owning class and constraining the field itself. The following example combines inheritance, generic parameters, and annotations:
```ql
predicate isFieldNode_2(DataFlow::Node node) {
     exists(Field f |
         // 1. Match the owning class through inheritance
         f.getDeclaringType().getSourceDeclaration().getASourceSupertype()
             .hasQualifiedName("org.package.name", "ParentClassName") and
         // 2. Match field conditions (OR logic)
         (
             // 2.1 Match a complex generic field type: ConcurrentHashMap<SubTypeNameA, SubTypeNameB>
             (
                 // a. Match the base type
                 // RULE: use .(RefType).getSourceDeclaration() to strip generic arguments and get the plain class declaration
                 f.getType().(RefType).getSourceDeclaration().hasQualifiedName("java.util.concurrent", "ConcurrentHashMap") and
                 // b. Match the 0th type argument (no cast needed when matching with hasName)
                 f.getType().(ParameterizedType).getTypeArgument(0).hasName("SubTypeNameA") and
                 // c. Match the 1st type argument (use the qualified name to avoid false positives; cast to RefType)
                 f.getType().(ParameterizedType).getTypeArgument(1).(RefType).hasQualifiedName("org.package.name", "SubTypeNameB")
             ) or
             // 2.2 Simple type name matching (lower precision)
             f.getType().hasName("TypeNameA") or
             // 2.3 Match by fully qualified name
             f.getType().(RefType).hasQualifiedName("org.package.name", "TypeNameB") or
             // 2.4 Match a field annotation
             f.getAnAnnotation().getType().hasName("Autowired")
         ) and 
         // 3. Bind field accesses (both reads and writes)
         node.asExpr() = f.getAnAccess()
     )
 }
```

> **Note**: the example demonstrates as many matching rules as possible for teaching purposes. In real rules, select only the conditions you need.

---

## III. Matching special nodes in taint analysis

Chapters I and II match single data-flow nodes, mainly to define the basic Source and Sink nodes of taint analysis. Taint analysis also involves:
- **Taint Propagator**: defines additional taint-propagation edges to keep paths continuous.

CodeQL taint analysis also has Barrier Guard, Neutral and other node kinds, but they are rarely used in this detection task and are not discussed here.

### 3.1 Taint Propagator

CodeQL ships many Taint Propagator rules for common third-party libraries. In a custom taint-analysis Config, add propagation edges by overriding `isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2)`.

By semantic characteristics, custom propagation rules fall into two categories: **Summary rules (method-level black-box propagation)** and **state/container rules (cross-method or instance binding)**.

#### 3.1.1 Summary propagation (method-level black box)

**Definition**: describes the macroscopic data flow inside one method call (e.g. "argument -> return value", "argument -> caller container").

**Mechanism and core rules**:

Summary propagation is implemented as QL rules inside `isAdditionalFlowStep`. Method matching must follow the **"declaration side first" and "strategy A"** rules from section 1.1; never use the call-side `c.getMethod()` directly.

Prefer concise **chained calls** that fetch the declaration-side class and method directly (see the patterns in section 1.2) without redundant intermediate variables; this matches CodeQL's Datalog evaluation and keeps the code clean.

**Standard template:**
```ql
// Summary propagation template: StringBuilder.append (argument -> container)
exists(Call c |
  // Chapter I rule: fetch the declaration-side class and method with a chain, using strategy A
  c.getCallee().getDeclaringType().getSourceDeclaration()
    .hasQualifiedName("java.lang", "StringBuilder") and
  c.getCallee().getSourceDeclaration().hasName("append") and
  
  // Bind data-flow nodes (argument -> caller container)
  n1.asExpr() = c.getArgument(0) and
  n2.asExpr() = c.getQualifier()
)
```

> **Note**: the Java third-party ecosystem is huge, so built-in rules cannot cover everything. For example, `StringBuilder.append` and `StringBuilder.toString` are not covered by default rules and must be added manually.

#### 3.1.2 State/container/field propagation (cross-method or instance binding)

**Definition**: not limited to the arguments and return value of one call, but describing the state flow of the **same object instance** across calls, or reads and writes of **global/static fields** across methods. This is where `isAdditionalFlowStep` is really needed.

**Typical patterns**:
1. **Custom container reads and writes**: e.g. the value passed to `CustomMap.put(k, v)` flows to the return value of `get(k)` on the same `CustomMap` instance.
2. **Cross-method flow of static/global fields**: method A writes a static field, method B reads it.

**IMPORTANT core rule (instance and semantic binding)**:

When matching across methods or calls, **never compare Qualifier AST nodes directly** (e.g. `putCall.getQualifier() = getCall.getQualifier()`): expressions at different code locations are different AST entities, so the comparison is always false across methods. Bind through **semantic entities** instead:
- **Field semantic binding**: introduce a `Field` entity variable and check whether both call qualifiers access the same underlying `Field` definition.

**Code example:**
```ql
// State/field propagation example: cross-method put -> get on a custom Map field
exists(MethodCall putCall, MethodCall getCall, Field targetField |
  // 1. Pin the semantic entity: constrain the field type
  targetField.getType().(RefType).getSourceDeclaration()
    .hasQualifiedName("com.package.name", "CustomizedMap") and
  
  // 2. Match the Put side (n1): taint flows into the value argument (index 1)
  // NOTE: for more precise matching of put (e.g. owning class), see the method rules in section 1.2
  putCall.getMethod().hasName("put") and
  n1.asExpr() = putCall.getArgument(1) and
  
  // 3. Match the Get side (n2): taint flows out of the return value of get
  getCall.getMethod().hasName("get") and
  n2.asExpr() = getCall and
  
  // 4. CORE RULE: bind semantically through the Field entity so put and get use the same field.
  // Cast the qualifier down to FieldAccess and compare the underlying Field entity.
  putCall.getQualifier().(FieldAccess).getField() = targetField and
  getCall.getQualifier().(FieldAccess).getField() = targetField
)
```

---

## IV. Fuzzy and batch matching rules

The examples above use exact matching. When target names are irregular or need batch coverage, CodeQL provides the following syntax.

### 4.1 Negation (`not`)

CodeQL supports negation with the `not` keyword:
```ql
predicate isFieldTest1(DataFlow::Node node) {
    exists(Field f |
      f.getDeclaringType().getSourceDeclaration().hasQualifiedName("org.package.name", "ClassName") and
      // Match all fields whose name is not "version"
      (not f.getName() = "version") and
      node.asExpr() = f.getAnAccess()
    )
}
```

### 4.2 Wildcard matching (`matches`)

CodeQL's `matches` follows SQL `LIKE` syntax: `%` matches zero or more characters and `_` matches a single character.

```
// 1. Match preTaskNodeList and preTasks
f.getName().matches("%Task%s%") or
// 2. Match only preTaskNodeList 
f.getName().matches("%Task______s%")
```

### 4.3 Regex matching (`regexpMatch`)

When wildcards are not expressive enough, use regex. Note that CodeQL's `regexpMatch` matches the whole string by default (implicitly `^` and `$`) and does not support a trailing `/i`; use the inline flag `(?i)` for case-insensitive matching.

```
// Match fields containing time or timeout, case-insensitively (e.g. waitStartTimeout, delayTime)
f.getName().regexpMatch("(?i).*(time|timeout).*")
```

### 4.4 Batch matching (`in`)

CodeQL supports batch matching with the `in` keyword:
```
// 1. Positive batch match
f.getName() in ["id", "name", "version", "code"] and

// 2. Negative batch match (exclude specific fields)
not (f.getName() in ["id", "name", "version", "code", "type", "loc"]) and
```
