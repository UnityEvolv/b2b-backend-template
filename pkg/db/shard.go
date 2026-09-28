package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ShardID names one Postgres cluster.
type ShardID int

// ShardMap says which shard holds an org. Today every org is on shard 0, but
// every query already asks, so adding a shard is a change to the map and not
// to every call site.
type ShardMap interface {
	ShardFor(ctx context.Context, orgID string) (ShardID, error)
}

// OneShard is the map with a single shard.
type OneShard struct{}

// ShardFor is always shard 0.
func (OneShard) ShardFor(context.Context, string) (ShardID, error) { return 0, nil }

// Cluster is a service's connection pools, one per shard, and the map that
// picks between them.
type Cluster struct {
	shards ShardMap
	pools  map[ShardID]*pgxpool.Pool
}

// NewCluster is a cluster with one pool per shard.
func NewCluster(shards ShardMap, pools map[ShardID]*pgxpool.Pool) *Cluster {
	return &Cluster{shards: shards, pools: pools}
}

// SingleShard is a cluster whose one pool is shard 0.
func SingleShard(pool *pgxpool.Pool) *Cluster {
	return NewCluster(OneShard{}, map[ShardID]*pgxpool.Pool{0: pool})
}

// ErrNoOrg means a tenant query was attempted without an org to route it by.
var ErrNoOrg = errors.New("db: org_id is required to route a tenant query")

func (c *Cluster) poolFor(ctx context.Context, orgID string) (*pgxpool.Pool, error) {
	if orgID == "" {
		return nil, ErrNoOrg
	}
	shard, err := c.shards.ShardFor(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("shard for org: %w", err)
	}
	pool, ok := c.pools[shard]
	if !ok {
		return nil, fmt.Errorf("db: no pool for shard %d", shard)
	}
	return pool, nil
}

// Read runs fn in a read-only transaction on the shard that holds orgID. A
// read needs an org to route by but no actor, since nothing is attributed.
func (c *Cluster) Read(ctx context.Context, orgID string, fn func(pgx.Tx) error) error {
	pool, err := c.poolFor(ctx, orgID)
	if err != nil {
		return err
	}
	return pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, fn)
}

// Ping checks every shard is reachable, for a readiness probe.
func (c *Cluster) Ping(ctx context.Context) error {
	for shard, pool := range c.pools {
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("shard %d: %w", shard, err)
		}
	}
	return nil
}

// Tx runs fn in a transaction on the shard that holds orgID, attributed to the
// actor in ctx. It is the one way a service writes tenant data: the org is
// passed explicitly, never inferred, and there is always someone to attribute
// the change to.
func (c *Cluster) Tx(ctx context.Context, orgID string, fn func(pgx.Tx) error) error {
	if orgID == "" {
		return ErrNoOrg
	}
	actor, ok := ActorFrom(ctx)
	if !ok {
		return ErrNoActor
	}
	pool, err := c.poolFor(ctx, orgID)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// Local to this transaction, so a pooled connection never carries
		// one caller's identity into the next.
		if _, err := tx.Exec(ctx, "SELECT set_config('app.actor', $1, true)", string(actor)); err != nil {
			return err
		}
		return fn(tx)
	})
}
