# app_finder

`app_finder` is a cross-platform Rust library designed to help retrieve information about installed applications on various operating systems. With this library, you can list all the installed apps, retrieve specific app details based on their address or file path, and export their icons.

## Supported OSes

It currently supports the following OSes (alphabetically sorted):

- macOS
- Windows

## Features

- List all installed applications on the system.
- Export application icons to a folder.
- Retrieve application icons as a base64 string.
- Find an application by its network address.
- Find an application by its installation path.

## Example Usage

Below is an example of how to use the `AppFinder` trait provided by the `app_finder` library:

```rust
use std::net::SocketAddr;
use std::path::Path;
use app_finder::{AppFinder, App};

// List all installed applications
let apps = AppFinder::list();
for app in apps {
    println!("App: {:?}", app);
}

// Export app icons to a folder
let folder_path = Path::new("/path/to/export/folder");
AppFinder::export_icons_to_folder(&apps, &folder_path, 64).unwrap();

// Get the base64-encoded icon of a specific app
let base64_icon = AppFinder::get_app_icon_base64(&apps[0], 64).unwrap();
println!("Base64 Icon: {}", base64_icon);

// Find an app by its network address
let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
if let Some(app) = AppFinder::get_app_by_addr(addr) {
    println!("App found by address: {:?}", app);
}

// Find an app by its installation path
let app_path = Path::new("/path/to/app");
if let Some(app) = AppFinder::get_app_by_path(app_path) {
    println!("App found by path: {:?}", app);
}
```
