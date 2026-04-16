//! Tiny RAII session pool. Checked-out items return to the pool on drop.

use std::ops::Deref;

use anyhow::Result;
use crossbeam_channel::{bounded, Receiver, Sender};

pub struct Pool<T> {
    rx: Receiver<T>,
    tx: Sender<T>,
}

impl<T> Pool<T> {
    /// Build a pool of `size` items by calling `make` for each slot.
    pub fn new<F>(size: usize, make: F) -> Result<Self>
    where
        F: Fn() -> Result<T>,
    {
        let (tx, rx) = bounded(size.max(1));
        for _ in 0..size.max(1) {
            tx.send(make()?).expect("fresh channel has capacity");
        }
        Ok(Self { rx, tx })
    }

    /// Block until an item is available, return a guard that releases on drop.
    pub fn checkout(&self) -> Guard<'_, T> {
        let item = self.rx.recv().expect("pool sender is still alive");
        Guard {
            item: Some(item),
            tx: &self.tx,
        }
    }
}

pub struct Guard<'a, T> {
    item: Option<T>,
    tx: &'a Sender<T>,
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.item.as_ref().expect("guard holds item until drop")
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            // If the pool is already dropped we'd get an error; that's fine.
            let _ = self.tx.send(item);
        }
    }
}
