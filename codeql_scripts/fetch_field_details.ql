// fetch_field_details.ql
//
// Position columns: bind `Location` to one variable so file / start_line /
// end_line all come from the same SourceLocation. Independent columns produce a
// cartesian product for declarations with the same name and start line.
//
// Javadoc columns (javadoc_file / javadoc_start_line / javadoc_end_line) are not
// selected: one declaration can have many Javadocs, and expanding them as
// separate columns multiplies the index rows. See fetch_class_details.ql.
//
// The field table has no body_end_line column; keep that column set unchanged.
import java

// Get the annotation start line if exists, else the start line of the declaration at loc
// (the else branch uses loc, because a merged entity yields multiple locations)
bindingset[f, loc]
int getAnnotationStartLine(Field f, Location loc) {
    if (f.hasAnnotation())
    then
        result = min(f.getAnAnnotation().getLocation().getStartLine())
    else
        result = loc.getStartLine()
}

// Get the modifer of the field
bindingset[f]
string getCallableModifier(Field f) {
    if (not f.hasNoModifier())
    then
        result = concat(f.getAModifier().toString(), ";")
    else
        result = ""
}

// Get the annotations of the field
bindingset[f]
string getCallableAnnotation(Field f) {
    if (f.hasAnnotation())
    then
        result = concat(f.getAnAnnotation().getType().getQualifiedName(), ";")
    else
        result = ""
}

// Get the qualified name of the field type
bindingset[f]
string getFieldTypeQualifiedName(Field f) {
    if (f.getType() instanceof RefType)
    then
        result = f.getType().(RefType).getQualifiedName()
    else
        result = f.getType().getName()
}

from Field f, Location loc
where
  f.fromSource() and
  f.getName() != "" and
  loc = f.getLocation()
select
  f.getName() as name,
  f.getDeclaringType().getSourceDeclaration().getQualifiedName() as class_qualified_name,
  f.getType() as type,
  getFieldTypeQualifiedName(f) as detailed_type,
  getCallableModifier(f) as modifiers,
  getCallableAnnotation(f) as annotations,
  loc.getFile().getRelativePath() as file,
  loc.getStartLine() as start_line,
  getAnnotationStartLine(f, loc) as annotations_start_line,
  loc.getEndLine() as end_line
