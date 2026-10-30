// fetch_func_details.ql
//
// Position columns: bind `Location` to one variable so file / start_line /
// body_end_line all come from the same SourceLocation, and collapse the
// multi-valued `Top.getTotalNumberOfLines()` with max().
//
// Javadoc columns (javadoc_file / javadoc_start_line / javadoc_end_line) are not
// selected: one declaration can have many Javadocs, and expanding them as
// separate columns multiplies the index rows. See fetch_class_details.ql.
//
// The function table has no end_line column (only body_end_line); keep that
// column set unchanged.
import java

// Get the annotation start line if exists, else the start line of the declaration at loc
// (the else branch uses loc, because a merged entity yields multiple locations)
bindingset[c, loc]
int getAnnotationStartLine(Callable c, Location loc) {
    if (c.hasAnnotation())
    then
        result = min(c.getAnAnnotation().getLocation().getStartLine())
    else
        result = loc.getStartLine()
}

// Get the modifer of the callable
bindingset[c]
string getCallableModifier(Callable c) {
    if (not c.hasNoModifier())
    then
        result = concat(c.getAModifier().toString(), ";")
    else
        result = ""
}

// Get the annotations of the callable
bindingset[c]
string getCallableAnnotation(Callable c) {
    if (c.hasAnnotation())
    then
        result = concat(c.getAnAnnotation().getType().getQualifiedName(), ";")
    else
        result = ""
}

// Get the Type of the Callable
bindingset[c]
string getCallableType(Callable c) {
    if (c instanceof Constructor)
    then result = "Constructor"
    else if (c instanceof Method)
    then result = "Method"
    else result = "Other Type"
}

from Callable c, Location loc
where
  c.fromSource() and
  c.getName() != "" and
  loc = c.getLocation()
select
  c.getName() as name,
  c.getDeclaringType().getSourceDeclaration().getQualifiedName() as class_qualified_name,
  getCallableType(c) as type_kind,
  c.getReturnType() as return_type,
  c.getStringSignature() as string_signature,
  getCallableModifier(c) as modifiers,
  getCallableAnnotation(c) as annotations,
  loc.getFile().getRelativePath() as file,
  loc.getStartLine() as start_line,
  getAnnotationStartLine(c, loc) as annotations_start_line,
  loc.getEndLine() + max(c.getTotalNumberOfLines()) as body_end_line
