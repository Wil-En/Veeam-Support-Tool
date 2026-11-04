#pragma once

// Pure SQL construction for the database console's guided query builder and schema wizard. No GUI, no
// platform types - std::string UTF-8 in and out - so the Win32 console, the Qt console, a unit test
// and the db_query_harness all build the SAME SQL. This is the single source of truth for identifier
// quoting and query shape; do not hand-build these strings anywhere else.
//
// Why quoting matters: Veeam's Postgres names tables with literal dots inside a schema, e.g.
// public."backup.model.ephosts". Unquoted, "backup.model.ephosts" is read as database.schema.table
// and fails with "cross-database references are not implemented". Every identifier is quoted as ONE
// token for the engine (Postgres double quotes, SQL Server brackets), with embedded quote characters
// escaped so a crafted name cannot break out of the quoted identifier.

#include <string>

namespace support_assist::gui::dbsql {

enum class Engine { postgres, sqlserver };

enum class Verb { select_, delete_, update_ };

// Quote one identifier (schema, table, or column) for the engine.
inline std::string quote_ident(Engine engine, const std::string& ident) {
  if (engine == Engine::postgres) {
    std::string out = "\"";
    for (const char c : ident) {
      out += c;
      if (c == '"')
        out += '"';  // "" escapes a double quote inside a quoted identifier
    }
    return out + "\"";
  }
  std::string out = "[";
  for (const char c : ident) {
    out += c;
    if (c == ']')
      out += ']';  // ]] escapes a bracket inside a bracketed identifier
  }
  return out + "]";
}

// A single-quoted string literal with embedded single quotes doubled (both engines).
inline std::string quote_literal(const std::string& value) {
  std::string out = "'";
  for (const char c : value) {
    out += c;
    if (c == '\'')
      out += '\'';
  }
  return out + "'";
}

// schema.table, each identifier quoted; schema omitted when empty.
inline std::string qualify_table(Engine engine, const std::string& schema, const std::string& table) {
  if (table.empty())
    return std::string();
  const std::string quoted = quote_ident(engine, table);
  return schema.empty() ? quoted : quote_ident(engine, schema) + "." + quoted;
}

// --- Schema introspection (the guided wizard's Scan / cascade) -------------------------------------

inline std::string scan_tables_sql(Engine engine) {
  return engine == Engine::postgres
             ? "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema "
               "NOT IN ('pg_catalog','information_schema') ORDER BY table_name"
             : "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = "
               "'BASE TABLE' ORDER BY table_name";
}

inline std::string scan_columns_sql(Engine /*engine*/, const std::string& schema,
                                    const std::string& table) {
  std::string sql =
      "SELECT column_name FROM information_schema.columns WHERE table_name = " + quote_literal(table);
  if (!schema.empty())
    sql += " AND table_schema = " + quote_literal(schema);
  sql += " ORDER BY ordinal_position";
  return sql;
}

inline std::string scan_values_sql(Engine engine, const std::string& schema, const std::string& table,
                                   const std::string& column) {
  const std::string qualified = qualify_table(engine, schema, table);
  const std::string qcol = quote_ident(engine, column);
  if (qualified.empty() || column.empty())
    return std::string();
  return engine == Engine::postgres
             ? "SELECT DISTINCT " + qcol + " FROM " + qualified + " ORDER BY 1 LIMIT 200"
             : "SELECT DISTINCT TOP 200 " + qcol + " FROM " + qualified + " ORDER BY 1";
}

// --- The guided query builder ---------------------------------------------------------------------

struct QuerySpec {
  Verb verb = Verb::select_;
  std::string schema;
  std::string table;
  std::string filter_column;  // WHERE column (optional)
  std::string op;             // comparison operator, defaults to "="
  std::string value;          // WHERE value (quoted as a literal)
  std::string order_column;   // SELECT ORDER BY column (optional)
  std::string order_dir;      // ASC / DESC, defaults to ASC
  std::string set_column;     // UPDATE SET column
  std::string set_value;      // UPDATE SET value (quoted as a literal)
};

// Build the SELECT / DELETE / UPDATE statement (terminated with ';'). Returns empty when no table.
inline std::string build_query(Engine engine, const QuerySpec& spec) {
  const std::string table = qualify_table(engine, spec.schema, spec.table);
  if (table.empty())
    return std::string();
  const std::string op = spec.op.empty() ? "=" : spec.op;
  // LIKE compares text: a date or number column is read as the text the console shows (SQL Server's
  // style 121 "2025-10-21 12:53:10.767"), not the server's own default form, which matches nothing typed.
  const std::string column = spec.filter_column.empty() ? std::string() : quote_ident(engine, spec.filter_column);
  const std::string compared = op != "LIKE" ? column
                               : engine == Engine::postgres ? "CAST(" + column + " AS text)"
                                                            : "CONVERT(nvarchar(4000), " + column + ", 121)";
  const std::string where =
      spec.filter_column.empty() ? std::string() : " WHERE " + compared + " " + op + " " + quote_literal(spec.value);

  std::string sql;
  switch (spec.verb) {
    case Verb::delete_:
      sql = "DELETE FROM " + table + where;
      break;
    case Verb::update_:
      sql = "UPDATE " + table + " SET " + quote_ident(engine, spec.set_column) + " = " +
            quote_literal(spec.set_value) + where;
      break;
    case Verb::select_:
    default:
      sql = "SELECT * FROM " + table + where;
      if (!spec.order_column.empty())
        sql += " ORDER BY " + quote_ident(engine, spec.order_column) + " " +
               (spec.order_dir.empty() ? "ASC" : spec.order_dir);
      break;
  }
  return sql + ";";
}

}  // namespace support_assist::gui::dbsql
