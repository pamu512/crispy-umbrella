use std::sync::atomic::{AtomicBool, Ordering};

/// GUI-visible runtime flags managed by Tauri (`AppHandle::state`).
#[derive(Debug)]
pub struct AppState {
    /// When true, [`crate::llm_proxy::invoke_local_llm`] prepends [`crate::dino_persona::DINO_SYSTEM_PROMPT`].
    pub is_dino_mode: AtomicBool,
}

impl AppState {
    pub fn new(dino_mode: bool) -> Self {
        Self {
            is_dino_mode: AtomicBool::new(dino_mode),
        }
    }

    pub fn dino_mode(&self) -> bool {
        self.is_dino_mode.load(Ordering::Relaxed)
    }

    pub fn set_dino_mode(&self, value: bool) {
        self.is_dino_mode.store(value, Ordering::Relaxed);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(false)
    }
}
