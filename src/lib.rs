#![cfg_attr(doc, doc = include_str!("../README.md"))]

pub mod platform;

use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use sysinfo::Pid;

pub use platform::App;
pub use platform::AppFinder;

pub trait AppCommon {
    fn list() -> Vec<App>;
    fn export_icons_to_folder(apps: &[App], folder_path: &PathBuf, size: u32) -> Result<()>;
    fn get_app_icon_base64(path: &PathBuf, size: u32) -> Result<String>;
    fn get_pid_by_addr(addr: SocketAddr) -> Option<Pid>;
    fn get_app_path_by_addr(addr: SocketAddr) -> Option<PathBuf>;
    fn get_app_by_addr(addr: SocketAddr) -> Option<App>;
    fn get_app_by_path(app_path: &PathBuf) -> Option<App>;
}

#[cfg(test)]
mod tests {
    use std::fs::read_dir;

    use super::*;
    use ctor::ctor;
    use log::{error, info, LevelFilter};

    #[ctor]
    fn init() {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Info) // 设置默认日志级别为info
            .init();
    }

    #[test]
    fn test_list() {
        let apps = AppFinder::list();
        assert!(apps.len() > 0);
    }

    #[test]
    fn test_export_icons_to_folder() {
        let apps = AppFinder::list();
        let folder_path = PathBuf::from("./icons");
        match AppFinder::export_icons_to_folder(&apps, &folder_path.clone(), 64) {
            Ok(_) => {
                // 检查 folder_path 下是否有 .png 文件
                let mut has_png_file = false;

                if let Ok(entries) = read_dir(folder_path.clone()) {
                    for entry in entries.filter_map(Result::ok) {
                        if let Some(extension) = entry.path().extension() {
                            if extension == "png" {
                                has_png_file = true;
                                break;
                            }
                        }
                    }
                }

                // 根据是否有 .png 文件来判断测试是否通过
                assert!(
                    has_png_file,
                    "Expected .png file(s) in folder {:?}",
                    folder_path
                );
            }
            Err(err) => {
                error!("Exec export_icons_to_folder failed: {:?}", err);
            }
        };
    }

    #[test]
    fn test_get_pid_by_addr() {
        let addr = find_tcp_addr().unwrap();
        info!("addr: {:?}", addr);
        let pid = AppFinder::get_pid_by_addr(addr);
        assert!(pid.is_some())
    }

    #[test]
    fn test_get_app_path_by_addr() {
        let addr = find_tcp_addr().unwrap();
        let app_path = AppFinder::get_app_path_by_addr(addr);
        info!("app_path: {:?}", app_path);
        assert!(app_path.is_some())
    }

    #[test]
    fn test_get_app_icon_base64() {
        let apps = AppFinder::list();
        let first_app = apps.first().unwrap().clone();
        match first_app.get_app_icon_base64(32) {
            Ok(icon_base64) => {
                info!("App icon base64: {}", icon_base64);
                // 判断是base64 图片格式的字符串
                assert!(icon_base64.starts_with("data:image/png;base64,"));
            }
            Err(err) => {
                error!("Exec get_app_icon_base64 failed: {:?}", err);
                assert!(false);
            }
        }
    }

    #[test]
    fn test_get_app_by_addr() {
        let addr = find_tcp_addr().unwrap();
        let app = AppFinder::get_app_by_addr(addr);
        match app {
            Some(app) => {
                info!("App: {:?}", app);
                assert!(true);
            }
            None => {
                error!("No app found for address: {:?}", addr);
                assert!(false);
            }
        }
    }

    #[test]
    fn test_get_app_by_path() {
        let apps = AppFinder::list();
        let first_app = apps.first().unwrap().clone();
        info!("App: {:?}", first_app);
        let path = first_app.path.clone();
        let app = AppFinder::get_app_by_path(&PathBuf::from(&path)).unwrap();
        // 判断app和first_app是否相等
        assert_eq!(app, first_app);
    }

    fn find_tcp_addr() -> Option<SocketAddr> {
        use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        if let Ok(sockets_info) = get_sockets_info(af_flags, proto_flags) {
            for si in sockets_info {
                // 匹配 TCP 协议的 socket 信息
                if let ProtocolSocketInfo::Tcp(tcp_info) = si.protocol_socket_info {
                    // 优先返回本地地址（local_addr），如果需要可以修改为返回远程地址
                    info!("Tcp found: {:?}", tcp_info);
                    // 判断local_addr不为0.0.0.0
                    return Some(SocketAddr::new(tcp_info.local_addr, tcp_info.local_port));
                }
            }
        }
        info!("Tcp Not found");
        None
    }
}

//新建一个tcp链接
