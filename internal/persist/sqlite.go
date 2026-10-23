package persist

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"scanning/internal/flow"
)

type SavedSession struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Mode       flow.Mode  `json:"mode"`
	Filter     string     `json:"filter"`
	CreatedAt  time.Time  `json:"createdAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`
	FlowCount  int64      `json:"flowCount"`
	ByteCount  int64      `json:"byteCount"`
	SavedAt    time.Time  `json:"savedAt"`
	Persistent bool       `json:"persistent"`
}

type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建会话数据库目录: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开会话数据库: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化会话数据库: %w", err)
	}
	schema := `
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	mode TEXT NOT NULL,
	filter TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	ended_at TEXT,
	flow_count INTEGER NOT NULL DEFAULT 0,
	byte_count INTEGER NOT NULL DEFAULT 0,
	saved_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flows (
	session_id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	id TEXT NOT NULL,
	payload TEXT NOT NULL,
	PRIMARY KEY (session_id, id)
);
CREATE INDEX IF NOT EXISTS idx_flows_session_seq ON flows(session_id, seq);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("创建会话表: %w", err)
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

func (d *DB) Save(ctx context.Context, session flow.Session, flows []*flow.Flow) (SavedSession, error) {
	now := time.Now()
	savedAt := now.Format(time.RFC3339Nano)
	var endedAt *string
	if session.EndedAt != nil {
		value := session.EndedAt.Format(time.RFC3339Nano)
		endedAt = &value
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return SavedSession{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO sessions(id, name, mode, filter, created_at, ended_at, flow_count, byte_count, saved_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name=excluded.name, mode=excluded.mode, filter=excluded.filter,
	created_at=excluded.created_at, ended_at=excluded.ended_at,
	flow_count=excluded.flow_count, byte_count=excluded.byte_count, saved_at=excluded.saved_at`,
		session.ID, session.Name, string(session.Mode), session.Filter,
		session.CreatedAt.Format(time.RFC3339Nano), endedAt, len(flows), session.ByteCount, savedAt); err != nil {
		return SavedSession{}, fmt.Errorf("写入会话: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM flows WHERE session_id = ?`, session.ID); err != nil {
		return SavedSession{}, fmt.Errorf("清理旧会话流量: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO flows(session_id, seq, id, payload) VALUES(?, ?, ?, ?)`)
	if err != nil {
		return SavedSession{}, err
	}
	defer stmt.Close()
	for i, f := range flows {
		if f == nil {
			continue
		}
		payload, err := json.Marshal(f)
		if err != nil {
			return SavedSession{}, fmt.Errorf("序列化 Flow %s: %w", f.ID, err)
		}
		if _, err := stmt.ExecContext(ctx, session.ID, i+1, f.ID, string(payload)); err != nil {
			return SavedSession{}, fmt.Errorf("写入 Flow %s: %w", f.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return SavedSession{}, err
	}
	return SavedSession{
		ID: session.ID, Name: session.Name, Mode: session.Mode, Filter: session.Filter,
		CreatedAt: session.CreatedAt, EndedAt: session.EndedAt,
		FlowCount: int64(len(flows)), ByteCount: session.ByteCount,
		SavedAt: now, Persistent: true,
	}, nil
}

func (d *DB) List(ctx context.Context) ([]SavedSession, error) {
	rows, err := d.db.QueryContext(ctx, `
SELECT id, name, mode, filter, created_at, ended_at, flow_count, byte_count, saved_at
FROM sessions ORDER BY saved_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SavedSession{}
	for rows.Next() {
		var item SavedSession
		var mode, createdAt, savedAt string
		var endedAt sql.NullString
		if err := rows.Scan(&item.ID, &item.Name, &mode, &item.Filter, &createdAt, &endedAt,
			&item.FlowCount, &item.ByteCount, &savedAt); err != nil {
			return nil, err
		}
		item.Mode = flow.Mode(mode)
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		item.SavedAt, _ = time.Parse(time.RFC3339Nano, savedAt)
		if endedAt.Valid {
			t, _ := time.Parse(time.RFC3339Nano, endedAt.String)
			item.EndedAt = &t
		}
		item.Persistent = true
		out = append(out, item)
	}
	return out, rows.Err()
}

func (d *DB) Load(ctx context.Context, id string) (flow.Session, []*flow.Flow, error) {
	var session flow.Session
	var mode, createdAt, savedAt string
	var endedAt sql.NullString
	err := d.db.QueryRowContext(ctx, `
SELECT id, name, mode, filter, created_at, ended_at, flow_count, byte_count
FROM sessions WHERE id = ?`, id).Scan(
		&session.ID, &session.Name, &mode, &session.Filter, &createdAt, &endedAt,
		&session.FlowCount, &session.ByteCount)
	if err == sql.ErrNoRows {
		return session, nil, os.ErrNotExist
	}
	if err != nil {
		return session, nil, err
	}
	session.Mode = flow.Mode(mode)
	session.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	session.Persistent = true
	if endedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, endedAt.String)
		session.EndedAt = &t
	}
	_ = savedAt

	rows, err := d.db.QueryContext(ctx, `SELECT payload FROM flows WHERE session_id = ? ORDER BY seq ASC`, id)
	if err != nil {
		return session, nil, err
	}
	defer rows.Close()
	items := []*flow.Flow{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return session, nil, err
		}
		var f flow.Flow
		if err := json.Unmarshal([]byte(payload), &f); err != nil {
			return session, nil, fmt.Errorf("解析已保存的 Flow: %w", err)
		}
		items = append(items, &f)
	}
	return session, items, rows.Err()
}

func (d *DB) Delete(ctx context.Context, id string) (bool, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM flows WHERE session_id = ?`, id); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return affected > 0, nil
}
