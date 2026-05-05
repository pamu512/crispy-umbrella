//! In-process background workers (Tokio). IOC crawler jobs use `mpsc` queues on the desktop host.

pub mod ioc_crawler;
pub mod scheduler;
