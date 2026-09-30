// Package notify decides who is told about what, how, and whether at all
// (UO-175): intake, routing by preference, quiet hours, suppression while
// someone is looking, dedupe and batching, and delivery to the feed, push,
// email and the daily digest. Nothing else in the platform sends a
// notification.
//
// What a notification can be about is pkg/notifycat's registry: each
// category's audience, default channels, quiet hours, batching and words.
// The router reads the category's flags and has no branch for any one.
package notify

import "time"

// BatchWindow is how long items of one group of a batched category collapse
// together.
const BatchWindow = 3 * time.Minute

// FeedLife is how long an entry stays in the feed.
const FeedLife = 30 * 24 * time.Hour
