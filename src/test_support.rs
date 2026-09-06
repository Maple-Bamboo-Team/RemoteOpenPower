use std::{fs, path::PathBuf};

pub(crate) struct TestDirectory(pub PathBuf);

impl TestDirectory {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rop-test-{}",
            hex::encode(crate::client::random_id())
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .recursive(false)
            .create(&path)
            .expect("create private test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            if std::thread::panicking() {
                crate::logging::log(
                    crate::logging::Level::Fatal,
                    format!("test cleanup failed {}: {error}", self.0.display()),
                );
            } else {
                panic!("test cleanup failed {}: {error}", self.0.display());
            }
        }
    }
}
