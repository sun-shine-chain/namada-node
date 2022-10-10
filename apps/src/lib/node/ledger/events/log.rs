//! A log to store events emitted by `FinalizeBlock` calls in the ledger.
//!
//! The log is flushed every other `N` block heights, where `N` is a
//! configurable parameter.

pub mod dumb_queries;

use std::sync::{Arc, RwLock};

use namada::types::storage::BlockHeight;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;

use crate::node::ledger::events::Event;

/// Run a CPU-bound task without blocking the Tokio runtime.
macro_rules! block_in_place {
    ($statement:expr) => {{
        // we need this because `tokio_test` panics if we
        // call `tokio::task::block_in_place()`
        #[cfg(test)]
        {
            $statement;
        }
        #[cfg(not(test))]
        {
            ::tokio::task::block_in_place(|| $statement);
        }
    }};
}

/// Soft lock on the maximum number of events the event log can hold.
///
/// If the number of events in the log exceeds this value, the log
/// will be pruned.
// TODO: make this a config param
const MAX_LOG_EVENTS: usize = 50000;

/// Soft lock on the number of entries the event log can hold.
///
/// If the difference between the newest log entry and the oldest's
/// block heights is greater than this value, the log will be pruned.
// TODO: make this a config param
const LOG_BLOCK_HEIGHT_DIFF: u64 = 1000;

/// Instantiates a new event log and its associated machinery.
///
/// General usage flow:
///
///   1. Spawn a new asynchronous task, with a [`Logger`]
///      running on a loop.
///   2. Send new events to the [`Logger`] with a [`LogEntrySender`].
///      This will alter the state of the [`EventLog`].
///   3. Concurrently, other asynchronous tasks may access the
///      [`EventLog`] to check for new events.
pub fn new() -> (EventLog, Logger, LogEntrySender) {
    let (tx, rx) = mpsc::unbounded_channel();

    let log = EventLog::new();
    let logger = Logger {
        receiver: rx,
        log: log.clone(),
    };
    let sender = LogEntrySender { sender: tx };

    (log, logger, sender)
}

/// Represents an entry in the event log.
#[derive(Debug)]
pub struct LogEntry {
    /// The block height at which we emitted the events.
    pub block_height: BlockHeight,
    /// The events emitted by a `FinalizeBlock` call.
    pub events: Vec<Event>,
}

/// Represents a node in the linked list of log entries.
#[derive(Debug)]
struct LogNode {
    entry: LogEntry,
    next: Option<Arc<LogNode>>,
}

/// Represents a log of [`Event`] instances emitted by
/// `FinalizeBlock` calls, in the ledger.
#[derive(Debug, Clone)]
pub struct EventLog {
    inner: Arc<EventLogInner>,
}

/// Contains a snapshot of the state of the [`EventLog`]
/// at some fixed point in time.
#[derive(Debug)]
#[allow(dead_code)]
struct EventLogSnapshot {
    oldest_height: BlockHeight,
    num_entries: usize,
    head: Arc<LogNode>,
}

/// Container for an event notifier and a lock, holding [`EventLog`] data.
#[derive(Debug)]
struct EventLogInner {
    /// A generator of notifications for RPC callers.
    notifier: event_listener::Event,
    /// Write protected data.
    lock: RwLock<EventLogInnerMux>,
}

/// Data which needs lock protection, in the [`EventLog`].
#[derive(Debug)]
struct EventLogInnerMux {
    /// The total number of entries in the log.
    num_entries: usize,
    /// The earliest block height in the event log.
    oldest_height: BlockHeight,
    /// Pointer to the freshest log entry.
    head: Option<Arc<LogNode>>,
}

/// Represents an iterator over the [`Event`] instances in the
/// event log, matching a given Tendermint-like query.
pub struct EventLogIterator<'a> {
    /// The current index pointing at the events in the `node` field.
    index: usize,
    /// A query to filter out events.
    query: dumb_queries::QueryMatcher<'a>,
    /// A pointer to one of the event log's entries.
    node: Option<Arc<LogNode>>,
}

impl<'a> Iterator for EventLogIterator<'a> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        Some(loop {
            let node = self.node.as_ref()?;
            match node.entry.events.get(self.index) {
                Some(event) => {
                    self.index += 1;
                    if self.query.matches(event) {
                        break event.clone();
                    }
                }
                None => {
                    self.index = 0;
                    self.node = node.next.clone();
                }
            }
        })
    }
}

/// Error returned by calling [`EventLog`] iteration methods.
#[derive(Debug)]
pub enum IterError {
    /// We failed to parse a query passed as argument.
    InvalidQuery,
    /// The event log has no entries.
    EmptyLog,
    /// We timed out waiting for log entries.
    Timeout,
}

impl EventLog {
    /// Returns a new iterator over this [`EventLog`], if the
    /// given `query` is valid and there are events present in
    /// the [`EventLog`].
    pub fn try_iter<'a>(
        &self,
        query: &'a str,
    ) -> Result<EventLogIterator<'a>, IterError> {
        let matcher = dumb_queries::QueryMatcher::parse(query)
            .ok_or(IterError::InvalidQuery)?;
        self.try_iter_with_matcher(matcher)
    }

    /// Just like [`EventLog::try_iter`], but uses a pre-compiled query matcher.
    pub fn try_iter_with_matcher<'a>(
        &self,
        matcher: dumb_queries::QueryMatcher<'a>,
    ) -> Result<EventLogIterator<'a>, IterError> {
        let snapshot = self.snapshot().ok_or(IterError::EmptyLog)?;
        Ok(EventLogIterator {
            index: 0,
            query: matcher,
            node: Some(snapshot.head),
        })
    }

    /// Waits up to `deadline` for new events, and if it succeeds,
    /// returns an iterator over these events.
    pub async fn wait_iter<'a>(
        &self,
        deadline: Instant,
        query: &'a str,
    ) -> Result<EventLogIterator<'a>, IterError> {
        let matcher = dumb_queries::QueryMatcher::parse(query)
            .ok_or(IterError::InvalidQuery)?;
        macro_rules! try_iter {
            () => {
                match self.try_iter_with_matcher(matcher.clone()) {
                    Ok(iter) => break Ok(iter),
                    Err(IterError::EmptyLog) => (),
                    err => break err,
                }
            };
        }
        tokio::time::timeout_at(deadline, async {
            loop {
                // do a couple of inline attempts to unlock the mutex with
                // some new events
                {
                    try_iter!();
                    try_iter!();
                    try_iter!();
                    try_iter!();
                }
                self.inner.notifier.listen().await;
            }
        })
        .await
        .map_err(|_| IterError::Timeout)
        .and_then(|result| result)
    }

    /// Creates a new event log.
    fn new() -> Self {
        Self {
            inner: Arc::new(EventLogInner {
                notifier: event_listener::Event::new(),
                lock: RwLock::new(EventLogInnerMux {
                    num_entries: 0,
                    oldest_height: 0.into(),
                    head: None,
                }),
            }),
        }
    }

    /// Prune the event log, ejecting old [`Event`] instances.
    fn prune(&self) {
        let _ = MAX_LOG_EVENTS;
        let _ = LOG_BLOCK_HEIGHT_DIFF;
        // TODO
    }

    /// Add a new entry to the log.
    fn add(&self, entry: LogEntry) {
        // update the log head
        {
            let mut log = self.inner.lock.write().unwrap();

            log.head = Some(Arc::new(LogNode {
                entry,
                next: log.head.take(),
            }));
            log.num_entries += 1;
        }

        // notify all event listeners
        self.inner.notifier.notify(usize::MAX);

        // we don't need to hold a lock to check
        // if the log needs to be pruned
        self.prune();
    }

    /// Snapshot the current state of the event log, and return it.
    fn snapshot(&self) -> Option<EventLogSnapshot> {
        let log = self.inner.lock.read().unwrap();
        log.head.clone().map(|head| EventLogSnapshot {
            head,
            num_entries: log.num_entries,
            oldest_height: log.oldest_height,
        })
    }
}

/// Receiver of new entries from a [`LogEntrySender`].
///
/// Received entries are logged to an [`EventLog`].
#[derive(Debug)]
pub struct Logger {
    log: EventLog,
    receiver: UnboundedReceiver<LogEntry>,
}

impl Logger {
    /// Receive new events from a `FinalizeBlock` call, and log them.
    ///
    /// We should use this method in a loop, such as:
    ///
    /// ```ignore
    /// let mut logger: Logger = /* ... */;
    ///
    /// loop {
    ///     if logger.log_new_entry().await.is_none() {
    ///         /* handle errors */
    ///     }
    /// }
    /// ```
    pub async fn log_new_entry(&mut self) -> Option<()> {
        let entry = self.receiver.recv().await?;
        block_in_place!(self.log.add(entry));
        Some(())
    }

    /// Call [`Self::log_new_entry`] repeatedly.
    pub async fn run(&mut self) -> Option<()> {
        loop {
            self.log_new_entry().await?;
        }
    }
}

/// Utility struct to log new entries in the ledger's [`EventLog`].
///
/// A [`LogEntrySender`] always has an associated [`Logger`],
/// which will receive log entries from the same sender and
/// log them in the [`EventLog`].
#[derive(Debug, Clone)]
pub struct LogEntrySender {
    sender: UnboundedSender<LogEntry>,
}

impl LogEntrySender {
    /// Send a new [`LogEntry`] to a [`Logger`].
    ///
    /// This call will fail if the associated [`Logger`] has been dropped.
    #[inline]
    pub fn send_new_entry(&self, entry: LogEntry) -> Option<()> {
        self.sender.send(entry).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::ledger::events::{EventLevel, EventType};

    /// Return a vector of mock `FinalizeBlock` events.
    fn mock_tx_events(hash: &str) -> Vec<Event> {
        let event_1 = Event {
            event_type: EventType::Accepted,
            level: EventLevel::Block,
            attributes: {
                let mut attrs = std::collections::HashMap::new();
                attrs.insert("hash".to_string(), hash.to_string());
                attrs
            },
        };
        let event_2 = Event {
            event_type: EventType::Applied,
            level: EventLevel::Block,
            attributes: {
                let mut attrs = std::collections::HashMap::new();
                attrs.insert("hash".to_string(), hash.to_string());
                attrs
            },
        };
        vec![event_1, event_2]
    }

    /// Test adding a couple of events to the event log, and
    /// reading those events back.
    #[test]
    fn test_log_add() {
        const NUM_HEIGHTS: u64 = 4;

        let (log, mut logger, sender) = new();

        // send events to the logger
        let events = mock_tx_events("DEADBEEF");

        for height in 0..NUM_HEIGHTS {
            sender.send_new_entry(LogEntry {
                block_height: height.into(),
                events: events.clone(),
            });
        }

        // receive events in the logger, and log them
        // to the event log
        tokio_test::block_on(async move {
            for _ in 0..NUM_HEIGHTS {
                logger.log_new_entry().await.unwrap();
            }
        });

        // inspect log
        let events_in_log: Vec<_> = log
            .try_iter("tm.event='NewBlock' AND accepted.hash='DEADBEEF'")
            .unwrap()
            .collect();

        assert_eq!(events_in_log.len(), NUM_HEIGHTS as usize);

        for i in 0..NUM_HEIGHTS {
            let i = i as usize;
            assert_eq!(events[0], events_in_log[i]);
        }
    }

    /// Test parallel log accesses.
    #[test]
    fn test_parallel_log_reads() {
        const NUM_CONCURRENT_READERS: usize = 4;
        const NUM_HEIGHTS: u64 = 4;

        let (log, mut logger, sender) = new();

        // send events to the logger
        let events = mock_tx_events("DEADBEEF");

        for height in 0..NUM_HEIGHTS {
            sender.send_new_entry(LogEntry {
                block_height: height.into(),
                events: events.clone(),
            });
        }

        // receive events in the logger, and log them
        // to the event log
        tokio_test::block_on(async move {
            for _ in 0..NUM_HEIGHTS {
                logger.log_new_entry().await.unwrap();
            }
        });

        // test reading the log in parallel
        let mut handles = vec![];

        for _ in 0..NUM_CONCURRENT_READERS {
            let log = log.clone();
            let events = events.clone();

            handles.push(std::thread::spawn(move || {
                let events_in_log: Vec<_> = log
                    .try_iter(
                        "tm.event='NewBlock' AND accepted.hash='DEADBEEF'",
                    )
                    .unwrap()
                    .collect();

                assert_eq!(events_in_log.len(), NUM_HEIGHTS as usize);

                for i in 0..NUM_HEIGHTS {
                    let i = i as usize;
                    assert_eq!(events[0], events_in_log[i]);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }
}
