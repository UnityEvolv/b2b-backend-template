package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Querier is anything that can run a read: a connection, a pool, a transaction.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// provenanceColumns must be on every table, NOT NULL, with these types.
var provenanceColumns = map[string]string{
	"created_by":       "text",
	"created_at":       "timestamp with time zone",
	"last_modified_by": "text",
	"last_modified_at": "timestamp with time zone",
}

type column struct {
	name, kind string
	notNull    bool
}

type table struct {
	oid     uint32
	name    string
	comment string
	columns map[string]column
}

// CheckConventions reads a schema's tables from the catalog and reports every
// way they break the table conventions (see docs/tables.md). An empty result
// means the schema conforms.
//
// It is run in CI against every service schema after every migration is
// applied, so a story that adds a table cannot forget them.
func CheckConventions(ctx context.Context, q Querier, schema string) ([]string, error) {
	tables, err := loadTables(ctx, q, schema)
	if err != nil {
		return nil, err
	}
	var problems []string
	report := func(t table, format string, args ...any) {
		problems = append(problems, fmt.Sprintf("%s.%s: ", schema, t.name)+fmt.Sprintf(format, args...))
	}

	for _, t := range tables {
		for name, kind := range provenanceColumns {
			c, ok := t.columns[name]
			switch {
			case !ok:
				report(t, "missing provenance column %s", name)
			case c.kind != kind:
				report(t, "%s is %s, want %s", name, c.kind, kind)
			case !c.notNull:
				report(t, "%s must be NOT NULL", name)
			}
		}
		for _, c := range t.columns {
			switch c.kind {
			case "timestamp without time zone":
				report(t, "%s is timestamp without time zone; use timestamptz", c.name)
			case "money", "real", "double precision":
				if strings.Contains(c.name, "amount") || strings.Contains(c.name, "price") || c.kind == "money" {
					report(t, "%s is %s; money is integer minor units plus a currency code", c.name, c.kind)
				}
			}
		}
		if id, ok := t.columns["id"]; ok && id.kind != "uuid" {
			report(t, "id is %s; ids are UUIDv7", id.kind)
		}

		hasTrigger, err := hasProvenanceTrigger(ctx, q, schema, t.oid)
		if err != nil {
			return nil, err
		}
		if !hasTrigger {
			report(t, "no provenance trigger: CREATE TRIGGER provenance BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION set_provenance()", t.name)
		}

		org, tenant := t.columns["org_id"]
		if !tenant {
			if !strings.HasPrefix(t.comment, "global:") {
				report(t, "no org_id; a table that is not per-org must say why with COMMENT ON TABLE %s IS 'global: <reason>'", t.name)
			}
			continue
		}
		if org.kind != "uuid" || !org.notNull {
			report(t, "org_id must be uuid NOT NULL")
		}
		leading, err := indexesNotLedByOrg(ctx, q, t.oid)
		if err != nil {
			return nil, err
		}
		for _, index := range leading {
			report(t, "index %s does not start with org_id; lead with org_id or say why with COMMENT ON INDEX %s IS 'global: <reason>'", index, index)
		}
		hasPK, err := hasPrimaryKey(ctx, q, t.oid)
		if err != nil {
			return nil, err
		}
		if !hasPK {
			report(t, "no primary key; tenant tables use PRIMARY KEY (org_id, id)")
		}
	}
	return problems, nil
}

func loadTables(ctx context.Context, q Querier, schema string) ([]table, error) {
	rows, err := q.Query(ctx, `
		SELECT c.oid, c.relname, coalesce(obj_description(c.oid, 'pg_class'), ''),
		       a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') AND c.relname <> 'goose_db_version'
		ORDER BY c.relname, a.attnum`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []table
	for rows.Next() {
		var (
			oid                    uint32
			name, comment, attname string
			kind                   string
			notNull                bool
		)
		if err := rows.Scan(&oid, &name, &comment, &attname, &kind, &notNull); err != nil {
			return nil, err
		}
		if len(tables) == 0 || tables[len(tables)-1].oid != oid {
			tables = append(tables, table{oid: oid, name: name, comment: comment, columns: map[string]column{}})
		}
		tables[len(tables)-1].columns[attname] = column{name: attname, kind: kind, notNull: notNull}
	}
	return tables, rows.Err()
}

func hasProvenanceTrigger(ctx context.Context, q Querier, schema string, oid uint32) (bool, error) {
	// tgtype bits: 1 row-level, 2 before, 4 insert, 16 update.
	rows, err := q.Query(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_trigger t
			JOIN pg_proc p ON p.oid = t.tgfoid
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE t.tgrelid = $1 AND p.proname = 'set_provenance' AND n.nspname = $2
			  AND (t.tgtype::int & 23) = 23 AND t.tgenabled <> 'D')`, oid, schema)
	return scanBool(rows, err)
}

func hasPrimaryKey(ctx context.Context, q Querier, oid uint32) (bool, error) {
	rows, err := q.Query(ctx, `SELECT EXISTS (SELECT 1 FROM pg_index WHERE indrelid = $1 AND indisprimary)`, oid)
	return scanBool(rows, err)
}

func indexesNotLedByOrg(ctx context.Context, q Querier, oid uint32) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT ic.relname
		FROM pg_index i
		JOIN pg_class ic ON ic.oid = i.indexrelid
		LEFT JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
		WHERE i.indrelid = $1 AND coalesce(a.attname, '') <> 'org_id'
		  -- A platform-wide lookup (a domain claim, the platform's list of
		  -- orgs) is allowed when the index says so; it lives on shard 0's
		  -- copy of the table the sharding story keeps global.
		  AND coalesce(obj_description(ic.oid, 'pg_class'), '') NOT LIKE 'global:%'
		ORDER BY ic.relname`, oid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func scanBool(rows pgx.Rows, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	return pgx.CollectExactlyOneRow(rows, pgx.RowTo[bool])
}
