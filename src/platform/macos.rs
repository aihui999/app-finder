use crate::AppCommon;
use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use base64::Engine;
use icns::IconFamily;
use log::warn;
use plist::{from_bytes, Value};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::{fs, net::SocketAddr, process::Command};
use sysinfo::{Pid, ProcessesToUpdate, System};

lazy_static::lazy_static! {
  pub static ref SYSTEM: Mutex<System> = Mutex::new(System::new());
}

#[derive(Debug, Deserialize, Clone)]
pub struct PlistAppInfo {
    _name: String,
    path: String,
    version: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Plist {
    _items: Vec<PlistAppInfo>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct App {
    pub name: String,
    pub path: String,
    pub version: Option<String>,
}

impl App {
    pub fn get_app_icon_base64(&self, size: u32) -> Result<String> {
        let path = PathBuf::from(&self.path);
        AppFinder::get_app_icon_base64(&path, size)
    }
}

#[derive(Debug)]
pub struct AppFinder {}

impl AppCommon for AppFinder {
    fn list() -> Vec<App> {
        let output = Command::new("/usr/sbin/system_profiler")
            .args(&["-xml", "-detailLevel", "mini", "SPApplicationsDataType"])
            .output()
            .expect("Failed to execute system_profiler");

        let plist_data: Vec<Plist> = from_bytes(&output.stdout).expect("Failed to parse plist");

        plist_data
            .get(0)
            .map(|plist| {
                plist
                    ._items
                    .iter()
                    .map(|app| App {
                        name: app._name.clone(),
                        path: app.path.clone(),
                        version: app.version.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn export_icons_to_folder(apps: &[App], folder_path: &PathBuf, size: u32) -> Result<()> {
        if !folder_path.exists() {
            fs::create_dir_all(folder_path).expect("Failed to create directory");
        }

        for app in apps {
            let output_path = folder_path.join(format!("{}.png", app.name));
            let icon_path = get_icns_path(&PathBuf::from(app.path.clone()));

            if icon_path.exists() {
                convert_icns_to_png(&icon_path, &output_path, size)?;
            }
        }
        Ok(())
    }

    fn get_app_icon_base64(path: &PathBuf, size: u32) -> Result<String> {
        // Attempt to open the file
        let file = File::open(&get_icns_path(path))?;

        let reader = BufReader::new(file);

        // Attempt to load the icon family from the file
        let icon_family = IconFamily::read(reader)?;

        let available_icons = icon_family.available_icons();
        let icon_type = match available_icons
            .iter()
            .find(|&icon_type| icon_type.pixel_width() == size)
            .copied()
        {
            Some(icon_type) => icon_type,
            None => {
                let default_icon = *available_icons.first().expect("No icons available");

                warn!(
                    "No icon of size {} found, using default icon : {:?}",
                    size, default_icon
                );
                default_icon
            }
        };
        // 获取指定大小的图片
        let image = icon_family.get_icon_with_type(icon_type)?;

        // Write the PNG to an in-memory buffer
        let mut buffer = Vec::new();
        {
            let mut cursor = Cursor::new(&mut buffer);
            image.write_png(&mut cursor)?;
        }

        // Encode the buffer to Base64
        let base64_encoded_png = general_purpose::STANDARD.encode(&buffer);

        // Return the Base64 encoded string
        Ok("data:image/png;base64,".to_owned() + base64_encoded_png.as_str())
    }

    fn get_pid_by_addr(addr: SocketAddr) -> Option<Pid> {
        if let Ok(pid) = get_pid(addr) {
            return Some(Pid::from(pid));
        }
        None
    }

    fn get_app_path_by_addr(addr: SocketAddr) -> Option<PathBuf> {
        if let Some(pid) = AppFinder::get_pid_by_addr(addr) {
            let mut system = SYSTEM.lock().unwrap();
            system.refresh_processes(ProcessesToUpdate::All, true);
            if let Some(process) = system.process(Pid::from(pid)) {
                let exe_path = process.exe()?.to_str()?.to_string();
                let app_path_string = format!("{}.app", exe_path.split(".app/").next()?);
                return Some(PathBuf::from(&app_path_string));
            }
            return None;
        }
        None
    }

    fn get_app_by_addr(addr: SocketAddr) -> Option<App> {
        let path = AppFinder::get_app_path_by_addr(addr)?;
        AppFinder::get_app_by_path(&path)
    }

    fn get_app_by_path(app_path: &PathBuf) -> Option<App> {
        // 获取 Info.plist 文件路径
        let info_plist_path = app_path.join("Contents/Info.plist");
        // 解析 Info.plist 文件
        if let Ok(plist_data) = read_plist(&info_plist_path) {
            let app_name = plist_data
                .as_dictionary()
                .and_then(|dict| dict.get("CFBundleName"))
                .and_then(|v| v.as_string())
                .unwrap_or("Unknown");
            // 应用程序名称和版本
            let app_version = plist_data
                .as_dictionary()
                .and_then(|dict| dict.get("CFBundleShortVersionString"))
                .and_then(|v| v.as_string())
                .unwrap_or("Unknown");
            // 输出应用程序信息
            Some(App {
                name: app_name.to_string(),
                path: app_path.to_str().unwrap().to_string(),
                version: Some(app_version.to_string()),
            })
        } else {
            None
        }
    }
}

fn get_pid(addr: SocketAddr) -> Result<usize> {
    // 获取port信息
    let port = addr.port();

    let output = Command::new("sh")
        .args(&[
            "-c",
            &format!("lsof -nP -iTCP:{} |grep \"{}->\"", port, port),
        ])
        .output()?;

    while let Some(line) = String::from_utf8_lossy(&output.stdout)
        .trim()
        .lines()
        .next()
    {
        let mut parts = line.trim().split_whitespace();
        // 确保有足够的字段
        if let (Some(_), Some(pid_str)) = (parts.next(), parts.next()) {
            if let Ok(pid) = pid_str.parse::<usize>() {
                return Ok(pid);
            }
        }
    }
    return Err(anyhow!("No PID found"));
}

fn convert_icns_to_png(icns_path: &PathBuf, output_path: &PathBuf, size: u32) -> Result<()> {
    Command::new("sips")
        .args(&[
            "-z",
            &size.to_string(),
            &size.to_string(),
            "-s",
            "format",
            "png",
            icns_path.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .status()?;
    Ok(())
}

fn read_plist(plist_path: &PathBuf) -> Result<plist::Value> {
    // 打开文件并创建一个读取器
    let file = File::open(&plist_path)?;
    let reader = BufReader::new(file);
    // 使用 plist crate 解析 plist 文件
    let plist_data = plist::Value::from_reader(reader)?;
    Ok(plist_data)
}

fn get_icns_path(path: &PathBuf) -> PathBuf {
    let p_path = path.join("Contents/Info.plist");
    let plist = Value::from_file(p_path);
    match plist {
        Ok(plist) => plist
            .as_dictionary()
            .and_then(|dict| dict.get("CFBundleIconFile").and_then(|value| value.as_string()))
            .map(|icns_path| {
                let full_path = path.join(format!("Contents/Resources/{}", icns_path));
                if icns_path.ends_with(".icns") {
                    full_path
                } else {
                    full_path.join(".icns")
                }
            })
            .unwrap_or_else(|| {
                PathBuf::from("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns")
            }),
        Err(_) => {
            return PathBuf::from(
                "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericApplicationIcon.icns",
            );
        }
    }
}
