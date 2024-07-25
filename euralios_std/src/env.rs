extern crate alloc;
use alloc::string::String;
use core::str::{self, from_utf8, Utf8Error};
use crate::{get_args, get_env,
            path::PathBuf,
            ffi::OsString};

pub fn args() -> impl Iterator<Item = String> {
    // Convert bytes into a vector of owned strings
    get_args()
        .split(|&b| b == 0x03)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
}

pub fn as_str() -> Result<&'static str, Utf8Error> {
    from_utf8(get_env())
}

pub struct Vars {
    envs: String,
    pos: usize
}

impl Iterator for Vars {
    type Item = (String, String);

    fn next(&mut self) -> Option<(String, String)> {
        if self.pos >= self.envs.len() {
            return None;
        }
        let remaining = &self.envs[self.pos..];

        // Records split using 0x03 bytes
        if let Some(pair) = remaining.split('\u{03}').next() {
            self.pos += pair.len() + 1;
            // Split pair by '='
            let mut key_value = pair.split('=');
            Some((String::from(key_value.next()?),
                  String::from(key_value.next()?)))
        } else {
            None
        }
    }
}

/// Returns an iterator over the (key, value) pairs
pub fn vars() -> Vars {
    if let Ok(envs) = as_str() {
        Vars {
            envs: String::from(envs),
            pos: 0
        }
    } else {
        Vars {
            envs: String::new(),
            pos: 0
        }
    }
}

#[derive(Debug)]
pub enum VarError {
    NotPresent,
    NotUnicode,
}

pub fn var(key: &str) -> Result<String, VarError> {
    let envs = as_str().map_err(|_| VarError::NotPresent)?;

    if let Some(pos) = envs.find(key) {
        if pos + key.len() == envs.len() {
            return Err(VarError::NotPresent);
        }
        let env_bytes = envs.as_bytes();

        // Check that the next character is '='
        if env_bytes[pos + key.len()] != b'=' {
            return Err(VarError::NotPresent);
        }

        // Value terminated by 0x03
        let value_bytes = &env_bytes[(pos + key.len() + 1)..];
        let mut value_len = 0;
        for b in value_bytes {
            if *b == 0x03 {
                break;
            }
            value_len += 1;
        }
        return Ok(String::from(
            unsafe {
                str::from_utf8_unchecked(&value_bytes[..value_len])
            }));
    }
    Err(VarError::NotPresent)
}

pub fn current_dir() -> Result<PathBuf, VarError> {
    let pwd = var("PWD")?;
    Ok(PathBuf::from(
        OsString::from(pwd)))
}
