use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use base64::Engine;
use serde::{Deserialize, Serialize};

use log::error;
use std::io::Cursor;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::Mutex;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use sysinfo::{Pid, ProcessesToUpdate, System};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows::Win32::UI::Controls::{IImageList, ILD_TRANSPARENT};

use winreg::{enums::*, RegKey, HKEY};

use windows::{
    core::PCWSTR,
    Win32::{
        Graphics::Gdi::*,
        UI::{
            Shell::*,
            WindowsAndMessaging::{DestroyIcon, GetIconInfoExW, HICON, ICONINFOEXW},
        },
    },
};

use widestring::U16CString;

use image::{DynamicImage, ImageBuffer, ImageFormat, RgbaImage};

use crate::AppCommon;

lazy_static::lazy_static! {
  pub static ref SYSTEM: Mutex<System> = Mutex::new(System::new());
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppFinder {}

impl AppCommon for AppFinder {
    fn list() -> Vec<App> {
        let system_apps = get_apps(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        );
        let system_apps_32 = get_apps(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        );

        let user_apps = get_apps(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        );

        let user_apps_32 = get_apps(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        );

        system_apps
            .into_iter()
            .chain(system_apps_32.clone())
            .chain(user_apps.clone())
            .chain(user_apps_32.clone())
            .collect::<Vec<App>>()
    }

    fn export_icons_to_folder(apps: &[App], folder_path: &PathBuf, size: u32) -> Result<()> {
        if !folder_path.exists() {
            fs::create_dir_all(folder_path).expect("Failed to create directory");
        }

        for app in apps {
            let output_path = folder_path.join(format!("{}.png", app.name));

            save_icon_from_exe(&PathBuf::from(&app.path), &output_path, size)?;
        }
        Ok(())
    }

    fn get_app_icon_base64(path: &PathBuf, size: u32) -> Result<String> {
        let image = get_image_from_exe(&PathBuf::from(path), size)?;
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);

        // 将图像编码为 PNG 格式并写入内存缓冲区
        image::DynamicImage::ImageRgba8(image.clone()).write_to(&mut cursor, ImageFormat::Png)?;

        let base64_encoded_png = general_purpose::STANDARD.encode(&buffer);

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
                return Some(PathBuf::from(&exe_path));
            }
            return None;
        }
        None
    }

    fn get_app_by_addr(addr: SocketAddr) -> Option<App> {
        if let Some(pid) = AppFinder::get_pid_by_addr(addr) {
            let mut system = SYSTEM.lock().unwrap();
            system.refresh_processes(ProcessesToUpdate::All, true);
            if let Some(process) = system.process(Pid::from(pid)) {
                return Some(App {
                    name: process.name().to_str()?.to_string(),
                    path: process.exe()?.to_str()?.to_string(),
                    version: None,
                });
            }
            return None;
        }
        None
    }

    fn get_app_by_path(_app_path: &PathBuf) -> Option<App> {
        None
    }
}

fn get_pid(addr: SocketAddr) -> Result<usize> {
    // 获取port信息
    let port = addr.port();
    let ip = addr.ip();

    let output = Command::new("cmd")
        .creation_flags(0x08000000)
        .args(&["/c", &format!("netstat -ano | findstr :{}", port)])
        .output()
        .expect("Failed to execute netstat");

    for line in String::from_utf8_lossy(&output.stdout).trim().lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();

        // 如果分割后的部分长度小于5，跳过
        if parts.len() < 5 {
            continue;
        }

        // 确保有足够的字段
        if parts[1].trim().contains(&format!("{}:{}", ip, port)) {
            // 尝试将第5个部分转换为整数并返回
            let pid = parts[4]
                .trim()
                .parse::<usize>()
                .map_err(|e| anyhow!("Failed to parse pid: {}", e))?;
            return Ok(pid);
        }
    }
    Err(anyhow!("Failed to get pid"))
}

fn get_apps(hive: HKEY, path: &str) -> Vec<App> {
    let mut apps = Vec::new();
    let hklm = RegKey::predef(hive);

    // 打开指定路径的注册表子键
    if let Ok(software_key) = hklm.open_subkey_with_flags(path, KEY_READ) {
        // 遍历所有子键
        for key in software_key.enum_keys().filter_map(Result::ok) {
            if let Ok(app_key) = software_key.open_subkey(&key) {
                // 获取应用程序的必要信息
                let name: String = app_key.get_value("DisplayName").unwrap_or_default();
                let install_location: String =
                    app_key.get_value("InstallLocation").unwrap_or_default();
                let version: String = app_key.get_value("DisplayVersion").unwrap_or_default();
                let icon: String = app_key.get_value("DisplayIcon").unwrap_or_default();

                // 如果应用名称或安装路径为空，跳过
                if name.is_empty() || install_location.is_empty() {
                    continue;
                }

                // 处理图标路径
                let icon_path_str = icon
                    .trim_matches('"')
                    .split(',')
                    .next()
                    .unwrap_or_default()
                    .to_string();

                let icon_path = Path::new(&icon_path_str);

                // 判断图标路径是否存在或有访问权限
                let app_path = if icon_path.exists() {
                    match icon_path.extension().and_then(|ext| ext.to_str()) {
                        Some("exe") => icon_path_str.clone(),
                        _ => install_location.clone(),
                    }
                } else {
                    install_location.clone()
                };

                apps.push(App {
                    name,
                    path: app_path,
                    version: Some(version),
                });
            }
        }
    }
    apps
}

fn save_icon_from_exe(app_path: &PathBuf, output_path: &PathBuf, size: u32) -> Result<()> {
    if !app_path.exists() {
        return Err(anyhow!("app path does not exist {:?}", app_path));
    }

    let parent = output_path
        .parent()
        .expect("Failed to get parent directory");

    if !parent.exists() {
        return Err(anyhow!("parent dir does not exist: {}", parent.display()));
    }

    match get_image_from_exe(app_path, size) {
        Ok(image) => {
            image.save(output_path).unwrap();
        }
        Err(e) => {
            error!("{:?}", e);
        }
    }

    Ok(())
}

fn get_image_from_exe(exe_path: &PathBuf, size: u32) -> Result<RgbaImage> {
    // 判断是否是exe文件
    if exe_path.extension().and_then(|ext| ext.to_str()) != Some("exe") {
        return Err(anyhow!("file is not exe: {}", exe_path.display()));
    }

    // 从指定的exe文件中解析icon
    unsafe {
        let path_str = U16CString::from_os_str(exe_path.as_os_str())?;
        let path_pcwstr = PCWSTR(path_str.as_ptr());

        // 获取图标索引
        let mut sfi = SHFILEINFOW::default();
        let hr = SHGetFileInfoW(
            path_pcwstr,
            FILE_ATTRIBUTE_NORMAL,
            Some(&mut sfi as *mut _ as _),
            std::mem::size_of::<SHFILEINFOW>() as _,
            SHGFI_SYSICONINDEX | SHGFI_LARGEICON,
        );

        if hr == 0 {
            return Err(anyhow!("SHGetFileInfoW failed"));
        }

        // 获取最大的图片
        let image_list: IImageList = SHGetImageList(SHIL_JUMBO as i32)?;

        // 通过图标索引获取图标句柄 (HICON)
        let hicon = image_list.GetIcon(sfi.iIcon as i32, ILD_TRANSPARENT.0)?;

        // Convert HICON to an image buffer (RgbaImage)
        let image_buffer = convert_hicon_to_image(&hicon)?;

        let _ = DestroyIcon(hicon);

        // Resize image to the desired size
        let resized = DynamicImage::ImageRgba8(image_buffer).resize_exact(
            size,
            size,
            image::imageops::CatmullRom,
        );

        Ok(resized.to_rgba8())
    }
}

fn convert_bgra_to_rgba(data: &mut [u8]) {
    for chunk in data.chunks_exact_mut(4) {
        chunk.swap(0, 2);
    }
}

fn convert_hicon_to_image(hicon: &HICON) -> Result<RgbaImage> {
    unsafe {
        let mut icon_info = ICONINFOEXW::default();
        // 图片大小
        icon_info.cbSize = std::mem::size_of::<ICONINFOEXW>() as u32;
        if !GetIconInfoExW(*hicon, &mut icon_info).as_bool() {
            return Err(anyhow!("GetIconInfoExW failed"));
        }
        let hdc_screen = CreateCompatibleDC(None);
        let hdc_mem = CreateCompatibleDC(hdc_screen);
        let hbm_old = SelectObject(hdc_mem, icon_info.hbmColor);
        let mut bm = BITMAP::default();
        if GetObjectW(
            icon_info.hbmColor,
            std::mem::size_of::<BITMAP>() as i32,
            Some(&mut bm as *mut _ as _),
        ) <= 0
        {
            return Err(anyhow!("GetObjectW failed"));
        }
        let mut bmp_info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: bm.bmWidth,
                biHeight: -bm.bmHeight,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut buffer: Vec<u8> = vec![0; (bm.bmWidth * 2 * bm.bmHeight * 2 * 4) as usize];
        if GetDIBits(
            hdc_mem,
            icon_info.hbmColor,
            0,
            bm.bmHeight as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut bmp_info,
            DIB_RGB_COLORS,
        ) == 0
        {
            return Err(anyhow!("GetDIBits failed"));
        }
        // Clean
        SelectObject(hdc_mem, hbm_old);
        let _ = DeleteDC(hdc_mem);
        let _ = DeleteDC(hdc_screen);
        let _ = DeleteObject(icon_info.hbmColor);
        let _ = DeleteObject(icon_info.hbmMask);
        // bgra->rgba
        convert_bgra_to_rgba(buffer.as_mut_slice());
        let image: RgbaImage =
            ImageBuffer::from_raw(bm.bmWidth as u32, bm.bmHeight as u32, buffer).unwrap();
        Ok(image)
    }
}
