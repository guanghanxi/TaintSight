import java

// Get the Type of the Callable
bindingset[c]
string getCallableType(Callable c) {
    if (c instanceof Constructor)
    then result = "Constructor"
    else if (c instanceof Method)
    then result = "Method"
    else result = "Other Type"
}

bindingset[api]
string getCallerContext(Call api) {
    if exists(Callable c | c = api.getCaller()) 
    then result = api.getCaller().getSourceDeclaration().getQualifiedName()
    else result = "<class-level-init>" 
}

from
    Call api
where
    api.getCallee().getStringSignature() != "()" and
    api.getCallee().getDeclaringType().getSourceDeclaration().getName() != "Object" and
    not api.getFile().getRelativePath().matches("%/test/%")
select
    // --- Callee Information ---
    // api as callstr,
    api.getCallee() as callee_name,
    api.getCallee().getDeclaringType().getSourceDeclaration().getQualifiedName() as callee_class,
    getCallableType(api.getCallee()) as callee_type,
    api.getCallee().getReturnType().getName() as callee_return_type,
    api.getCallee().getStringSignature() as callee_signature,
    // api.getCaller().getSourceDeclaration().getQualifiedName() as caller,
    // --- Caller Information ---
    getCallerContext(api) as caller_context,
    api.getFile().getRelativePath() as caller_file,
    api.getLocation().getStartLine() as caller_start_line,
    api.getLocation().getEndLine() as caller_end_line