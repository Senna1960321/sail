//! Whether a file was written since it was read, by its size and time of
//! modification: for what reads a file and watches it only later, and for
//! what never watches it and must know, at a reload, whether to read it
//! again.

/// A file's size and time of modification, and what it holds where those
/// cannot tell, taken just before it is read: what a file is read against.
/// A file is read when what it configures is built, and watched only
/// later, at a start seconds later; a write in between raises no event,
/// and without this would never apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    len: u64,
    modified: std::time::SystemTime,
    /// Where the file was modified less than `RACY` before the stamp was
    /// taken, what it held then (`None` if it could not be read): a write
    /// in the same tick leaves its size and time as they were.
    content: Option<Option<u64>>,
}

/// A file modified this close before its stamp was taken may be written
/// again without its time of modification changing, as git treats an
/// index entry as old as the index: a file system keeps the time to a
/// tick, Linux's coarse clock (4 ms at HZ=250, 10 at HZ=100), or to the
/// second or two (ext3, HFS+, FAT).
const RACY: std::time::Duration = std::time::Duration::from_secs(2);

impl Stamp {
    pub(crate) fn of(path: &std::path::Path) -> Option<Self> {
        let taken = std::time::SystemTime::now();
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok()?;
        let racy = modified
            .checked_add(RACY)
            .is_none_or(|settled| settled >= taken);
        Some(Stamp {
            len: meta.len(),
            modified,
            content: racy.then(|| content(path)),
        })
    }
}

/// A digest of what `path` holds, if it can be read.
fn content(path: &std::path::Path) -> Option<u64> {
    use std::hash::Hasher;
    let data = std::fs::read(path).ok()?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(&data);
    Some(hasher.finish())
}

/// Whether `path` may have been written since `read` was taken of it: it
/// is not as it was then; or it is there and was not; or, modified too
/// close to then for its time to tell, it holds something else now. A
/// file that is gone or cannot be looked at was not: reading it would
/// only fail.
pub(crate) fn written_since(read: Option<Stamp>, path: &std::path::Path) -> bool {
    let Some(meta) = std::fs::metadata(path).ok() else {
        return false;
    };
    let Some(read) = read else {
        return true;
    };
    if meta.len() != read.len || meta.modified().ok() != Some(read.modified) {
        return true;
    }
    match read.content {
        None => false,
        Some(None) => true,
        Some(held) => content(path) != held,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sail-stamp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn set_modified(path: &std::path::Path, at: std::time::SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }

    /// A stamp tells a file written since from one left alone, and one
    /// that appeared; a file that is gone was not written.
    #[test]
    fn a_stamp_tells_a_file_written_since() {
        let dir = dir();
        let path = dir.join("file");
        assert!(!written_since(None, &path), "not there, then or now");
        std::fs::write(&path, "one").unwrap();
        assert!(written_since(None, &path), "there now, and was not");
        let read = Stamp::of(&path);
        assert!(!written_since(read, &path), "left alone");
        std::fs::write(&path, "another").unwrap();
        assert!(written_since(read, &path), "written since");
        std::fs::remove_file(&path).unwrap();
        assert!(!written_since(read, &path), "gone");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A write of the same length in the same tick as the one before the
    /// stamp leaves the file's size and time as they were: what it holds
    /// tells it, and the same content again is no write.
    #[test]
    fn a_write_in_the_same_tick_is_told_by_its_content() {
        let dir = dir();
        let path = dir.join("file");
        std::fs::write(&path, "a.example").unwrap();
        let read = Stamp::of(&path).unwrap();
        assert!(read.content.is_some(), "just written: racy");
        std::fs::write(&path, "b.example").unwrap();
        set_modified(&path, read.modified);
        assert!(written_since(Some(read), &path), "written in the same tick");
        std::fs::write(&path, "a.example").unwrap();
        set_modified(&path, read.modified);
        assert!(!written_since(Some(read), &path), "the same content again");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A file modified well before its stamp is not read for it: its next
    /// write gets a later time.
    #[test]
    fn a_settled_file_is_stamped_by_its_time_alone() {
        let dir = dir();
        let path = dir.join("file");
        std::fs::write(&path, "one").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        set_modified(&path, old);
        let read = Stamp::of(&path).unwrap();
        assert_eq!(read.content, None);
        assert!(!written_since(Some(read), &path), "left alone");
        std::fs::write(&path, "two").unwrap();
        assert!(written_since(Some(read), &path), "written since");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
