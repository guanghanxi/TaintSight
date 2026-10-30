// fetch_class_locs.ql
//
// Position columns: bind `Location` to one variable so file / start_line /
// end_line all come from the same SourceLocation, and collapse the multi-valued
// `Top.getTotalNumberOfLines()` with max(). Independent columns produce a
// cartesian product for declarations with the same name and start line (a class
// from one file paired with line counts from another).
//
// This table has no javadoc columns. Its line ranges are used by match validation.
import java

from
  ClassOrInterface c, Location loc
where
  c.fromSource() and
  c.getName() != "" and
  loc = c.getLocation()
select
  c.getName() as name,
  c.getQualifiedName() as qualified_name,
  loc.getFile().getRelativePath() as file,
  loc.getStartLine() as start_line,
  loc.getEndLine()  + max(c.getTotalNumberOfLines()) as end_line
