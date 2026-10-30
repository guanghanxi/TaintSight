// fetch_class_details.ql
//
// Position columns: bind `Location` to one variable so file / start_line /
// end_line / body_end_line all come from the same SourceLocation, and collapse
// the multi-valued `Top.getTotalNumberOfLines()` with max(). Expanding these as
// independent select columns produces a cartesian product for declarations with
// the same name and start line (e.g. the same class present in src/main and
// src/test and merged by the extractor): mutually inconsistent line numbers
// under one (file, start_line) key, or a class from one file paired with line
// counts from another. Binding one Location keeps the position columns
// consistent for each entity key.
//
// Javadoc columns: javadoc_file / javadoc_start_line / javadoc_end_line are not
// selected. Expanding each from `getDoc().getJavadoc()` independently lets the
// three values come from different Javadocs, and one declaration may have many
// Javadocs, which multiplies index rows. No Python code reads these columns
// (`symbol_ops.py` selects by column name, and the evaluator uses only the
// location tables); if javadoc data is needed later, add a separate query that
// joins by entity identity rather than adding columns to the entity table.
import java

// Get the annotation start line if exists, else the start line of the declaration at loc
// (the else branch uses loc, because a merged entity yields multiple locations)
bindingset[c, loc]
int getAnnotationStartLine(RefType c, Location loc) {
    if (c.hasAnnotation())
    then
        result = min(c.getAnAnnotation().getLocation().getStartLine())
    else
        result = loc.getStartLine()
}

// Get the modifer of the class
bindingset[c]
string getRefTypeModifier(RefType c) {
    if (not c.hasNoModifier())
    then
        result = concat(c.getAModifier().toString(), ";")
    else
        result = ""
}

// Get the annotations of the class
bindingset[c]
string getRefTypeAnnotation(RefType c) {
    if (c.hasAnnotation())
    then
        result = concat(c.getAnAnnotation().getType().getQualifiedName(), ";")
    else
        result = ""
}

// Get the Type of the RefType
bindingset[c]
string getRefTypeKind(RefType c) {
    if (c instanceof ParameterizedClass)
    then result = "Parameterized Class"
    else if (c instanceof ParameterizedInterface)
    then result = "Parameterized Interface"
    else if (c instanceof EnumType)
    then result = "Enum Type"
    else if (c instanceof AnnotationType)
    then result = "Annotation Type"
    else if (c instanceof Interface)
    then result = "Interface"
    else if (c instanceof Class)
    then result = "Class"
    else result = "Other Kind"
}

from RefType c, Location loc
where
  c.fromSource() and
  c.getName() != "" and
  loc = c.getLocation()
select
  c.getName() as name,
  c.getQualifiedName() as qualified_name,
  getRefTypeKind(c) as type_kind,
  getRefTypeModifier(c) as modifiers,
  getRefTypeAnnotation(c) as annotations,
  concat(c.getAStrictAncestor().getSourceDeclaration().getQualifiedName(), "; ") as super_types,
  loc.getFile().getRelativePath() as file,
  loc.getStartLine() as start_line,
  getAnnotationStartLine(c, loc) as annotations_start_line,
  loc.getEndLine() as end_line,
  loc.getEndLine() + max(c.getTotalNumberOfLines()) as body_end_line
