// fetch_func_locs.ql
//
// Position columns: bind `Location` to one variable so file / start_line /
// end_line all come from the same SourceLocation, and collapse the multi-valued
// `Top.getTotalNumberOfLines()` with max() (see fetch_class_locs.ql).
//
// This table has no javadoc columns. Its row count is also used as the
// "project method count" denominator by the CodeQL agent.
import java

from
  Callable c, Location loc
where
  c.fromSource() and
  c.getName() != "" and
  loc = c.getLocation()
select
  c.getName() as name,
  loc.getFile().getRelativePath() as file,
  loc.getStartLine() as start_line,
  loc.getEndLine() + max(c.getTotalNumberOfLines()) as end_line
