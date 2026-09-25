//! `paguro service console`: the service in the foreground (debugging,
//! tests). `--mock` serves `MockApi::demo()`, an in-memory machine: nothing
//! real is touched. On Unix it serves a socket (`--unix PATH`, default
//! `/tmp/CoreFxPipe_<pipe>`, where .NET's named pipes look), for the C# front
//! ends' tests on Linux.

use std::sync::Arc;

use paguro_win::api::WinApi;

use crate::Worker;

fn usage() -> ! {
    eprintln!(
        "usage: paguro service console [--mock] [--pipe NAME] [--unix PATH] [--as user|admin|elevated]"
    );
    std::process::exit(2)
}

/// `paguro service console [--mock] [--pipe NAME] [--unix PATH] [--as user|admin|elevated]`.
pub fn console(args: &[String]) {
    let mut mock = false;
    let mut pipe = paguro_win::rpc::PIPE_NAME.to_string();
    let mut unix: Option<String> = None;
    let mut who = "admin".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mock" => mock = true,
            "--pipe" => pipe = it.next().cloned().unwrap_or_else(|| usage()),
            "--unix" => unix = it.next().cloned(),
            "--as" => who = it.next().cloned().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|m: &str| eprintln!("paguro service: {m}"));
    let make: crate::MakeApi = if mock {
        Box::new(|| Box::new(paguro_win::mock::MockApi::demo()) as Box<dyn WinApi>)
    } else {
        #[cfg(windows)]
        {
            Box::new(|| Box::new(paguro_win::real::RealApi::new()) as Box<dyn WinApi>)
        }
        #[cfg(not(windows))]
        {
            eprintln!("paguro service: not Windows: only --mock");
            std::process::exit(2)
        }
    };
    let l2 = log.clone();
    let worker = Arc::new(Worker::spawn(
        make,
        true,
        Box::new(move |api| crate::startup(api, &|m| l2(m))),
    ));
    let _ = (&pipe, &unix, &who);
    #[cfg(unix)]
    {
        let caller = paguro_win::rpc::Caller {
            user: who.clone(),
            admin: who != "user",
            elevated: who == "elevated",
            pid: None,
        };
        let path = unix.unwrap_or_else(|| format!("/tmp/CoreFxPipe_{pipe}"));
        log(&format!("serving {path} as {who}"));
        if let Err(e) = crate::serve_unix(std::path::Path::new(&path), worker, caller) {
            log(&format!("{path}: {e}"));
            std::process::exit(1);
        }
    }
    #[cfg(windows)]
    {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        log(&format!("serving \\\\.\\pipe\\{pipe}"));
        if let Err(e) = crate::win::serve_pipe(&pipe, worker, stop, log.clone()) {
            log(&format!("pipe {pipe}: {e}"));
            std::process::exit(1);
        }
    }
}
