// All GUI logic lives in the React frontend, which communicates with
// the Rust engine via HTTP on localhost:7878. This file just boots
// the Tauri window. Add #[tauri::command] functions here later if you
// want to call OS APIs directly from the React side without HTTP.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running RustShield GUI");
}
