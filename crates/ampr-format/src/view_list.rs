//! Lists a directory of the compiled index view: child directories, then packed files.
//!
//! This listing serves packed directories, so a child directory is listed
//! only when it has a packed file below it (`DIR_PACKED`), and a file only
//! when a join linked it. A packed file whose folded key is also a listed
//! directory's key is skipped: the name lists once, as the directory, as
//! today's listing walk does (`overlay::next_child`). Entries come in no
//! particular order. A cursor names the entry `next` returns, so it is
//! `Copy` and `first` rewinds it.
use crate::view::{View, DIR_PACKED, NONE};

/// Where a listing stands: the next child directory, the next packed file,
/// or the end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cursor {
    Dirs(u32),
    Files(u32),
    Done,
}

/// One listed name: a directory id or a file id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry {
    Dir(u32),
    File(u32),
}

impl View<'_> {
    /// The cursor at the first entry of directory `dir`; `Done` for an id
    /// out of range or a directory with nothing packed below it.
    pub fn first(&self, dir: u32) -> Cursor {
        if dir == NONE || dir > self.dir_count() {
            return Cursor::Done;
        }
        let d = self.dir(dir);
        match self.packed_dir_from(d.first_dir) {
            NONE => self.files_from(d.first_file),
            c => Cursor::Dirs(c),
        }
    }

    /// The entry at `c` and the cursor after it; `(None, Done)` at the end.
    pub fn next(&self, c: Cursor) -> (Option<Entry>, Cursor) {
        match c {
            Cursor::Dirs(id) => {
                let d = self.dir(id);
                let after = match self.packed_dir_from(d.next_sibling) {
                    NONE => self.files_from(self.dir(d.parent).first_file),
                    s => Cursor::Dirs(s),
                };
                (Some(Entry::Dir(id)), after)
            }
            Cursor::Files(id) => (Some(Entry::File(id)), self.files_from(self.next_file(id))),
            Cursor::Done => (None, Cursor::Done),
        }
    }

    /// The first `DIR_PACKED` directory from `id` on along the sibling
    /// chain, `NONE` when there is none.
    fn packed_dir_from(&self, mut id: u32) -> u32 {
        while id != NONE && self.dir(id).flags & DIR_PACKED == 0 {
            id = self.dir(id).next_sibling;
        }
        id
    }

    /// The cursor at the first listed file from `id` on along the packed
    /// chain, `Done` when there is none.
    fn files_from(&self, mut id: u32) -> Cursor {
        while id != NONE && self.key_is_listed_dir(id) {
            id = self.next_file(id);
        }
        if id == NONE {
            Cursor::Done
        } else {
            Cursor::Files(id)
        }
    }

    /// Whether packed file `id`'s folded key is also the key of a
    /// `DIR_PACKED` directory, which lists in its place.
    fn key_is_listed_dir(&self, id: u32) -> bool {
        let dirs = self.dirs();
        self.dirs_by_hash(self.hash(id))
            .any(|d| dirs[d as usize - 1].flags & DIR_PACKED != 0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::index::{tests::image, Index};
    use crate::source::PATH_BUF;
    use crate::view::{build, sizes, Buffers, Dir, Packs};
    use std::collections::HashMap;
    use std::vec::Vec;
    use std::{format, vec};

    /// Builds a view over `paths` (ids in order), links the ids `packed`
    /// picks, and hands the view and the image to `f`.
    fn with_view(paths: &[Vec<u8>], packed: impl Fn(u32) -> bool, f: impl FnOnce(View<'_>, &[u8])) {
        let refs: Vec<&[u8]> = paths.iter().map(|p| &p[..]).collect();
        let img = image(&refs);
        let idx = Index::open(&img[..]).unwrap();
        let files = idx.len();
        let dir_cap = files / 8 + 1024;
        let sz = sizes(files, dir_cap).unwrap();
        let (next, chunk, lz4) = sz.pack_columns(Packs::Lz4);
        let n = files as usize;
        let (mut hash, mut size, mut mtime, mut path_at) =
            (vec![0; n], vec![0; n], vec![0; n], vec![0; n]);
        let (mut next, mut chunk, mut lz4_hash) = (vec![0; next], vec![0; chunk], vec![0; lz4]);
        let mut slots = vec![0; sz.file_slots as usize];
        let mut dirs = vec![Dir::default(); dir_cap as usize];
        let mut dir_slots = vec![0; sz.dir_slots as usize];
        let (mut collide, mut dir_of) = (vec![0; 256], vec![0; n]);
        let bufs = Buffers {
            hash: &mut hash,
            size: &mut size,
            mtime: &mut mtime,
            path_at: &mut path_at,
            next: &mut next,
            chunk: &mut chunk,
            slots: &mut slots,
            dirs: &mut dirs,
            dir_slots: &mut dir_slots,
            collide: &mut collide,
            dir_of: &mut dir_of,
            lz4_hash: &mut lz4_hash,
        };
        let mut b = build(&idx, bufs).unwrap();
        for id in (1..=files).filter(|&id| packed(id)) {
            b.link_packed(id);
        }
        f(b.finish(), &img);
    }

    /// Folded name to "is a directory" for every entry from `first(dir)`,
    /// asserting each folded name lists once.
    fn listed(v: &View<'_>, img: &[u8], dir: u32, from: Cursor) -> HashMap<Vec<u8>, bool> {
        let mut buf = [0u8; PATH_BUF];
        let cut = usize::from(v.dir(dir).key_len) + 1;
        let (mut out, mut c) = (HashMap::new(), from);
        loop {
            let (e, after) = v.next(c);
            let (name, is_dir) = match e {
                None => break,
                Some(Entry::Dir(d)) => {
                    (v.dir_path(img, d, &mut buf).unwrap()[cut..].to_vec(), true)
                }
                Some(Entry::File(f)) => (v.path(img, f, &mut buf).unwrap()[cut..].to_vec(), false),
            };
            assert!(out.insert(name.to_ascii_lowercase(), is_dir).is_none());
            c = after;
        }
        assert_eq!(c, Cursor::Done);
        out
    }

    /// The immediate children of folded key `key` among the packed paths,
    /// a directory winning over a file of its folded name.
    fn expected(
        paths: &[Vec<u8>],
        packed: &impl Fn(u32) -> bool,
        key: &[u8],
    ) -> HashMap<Vec<u8>, bool> {
        let mut out = HashMap::new();
        for (i, p) in paths.iter().enumerate() {
            let p = p.to_ascii_lowercase();
            if !packed(i as u32 + 1)
                || p.len() <= key.len()
                || &p[..key.len()] != key
                || p[key.len()] != b'/'
            {
                continue;
            }
            let rest = &p[key.len() + 1..];
            match rest.iter().position(|&c| c == b'/') {
                Some(k) => {
                    out.insert(rest[..k].to_vec(), true);
                }
                None => {
                    out.entry(rest.to_vec()).or_insert(false);
                }
            }
        }
        out
    }

    /// 300 paths in mixed case under nested directories, plus files named
    /// as a sibling directory (`/app0/Data/S1`, `/app0/data/s2/D1`) and one
    /// named as a directory with nothing packed (`/app0/Only/2`).
    fn nested_paths() -> Vec<Vec<u8>> {
        let mut paths: Vec<Vec<u8>> = (0..300u32)
            .map(|i| {
                let top = if i % 2 == 0 { "Data" } else { "data" };
                match i % 6 {
                    0 => format!("/app0/F{i}.bin"),
                    1 => format!("/app0/{top}/f{i}.bin"),
                    2 => format!("/app0/Only/{i}/deep{i}.bin"),
                    _ => format!("/app0/{top}/S{}/d{}/x{i}.bin", i % 4, i % 3),
                }
                .into_bytes()
            })
            .collect();
        paths.push(b"/app0/Data/S1".to_vec());
        paths.push(b"/app0/data/s2/D1".to_vec());
        paths.push(b"/app0/Only/2".to_vec());
        paths
    }

    /// Packs ids not divisible by 3, the three dir-named files, and nothing
    /// under `/app0/Only/1*`.
    fn packed_ids(paths: &[Vec<u8>]) -> impl Fn(u32) -> bool + '_ {
        move |id| {
            let p = &paths[id as usize - 1];
            id as usize > 300 || (id % 3 != 0 && !p.starts_with(b"/app0/Only/1"))
        }
    }

    #[test]
    fn every_directory_lists_its_packed_children_once() {
        let paths = nested_paths();
        let packed = packed_ids(&paths);
        with_view(&paths, &packed, |v, img| {
            let mut buf = [0u8; PATH_BUF];
            let (mut empty, mut full) = (0, 0);
            for dir in 1..=v.dir_count() {
                let key = v.dir_path(img, dir, &mut buf).unwrap().to_ascii_lowercase();
                let want = expected(&paths, &packed, &key);
                let got = listed(&v, img, dir, v.first(dir));
                assert_eq!(got, want, "{}", std::string::String::from_utf8_lossy(&key));
                assert_eq!(listed(&v, img, dir, v.first(dir)), got);
                if want.is_empty() {
                    assert_eq!(v.first(dir), Cursor::Done);
                    empty += 1;
                } else {
                    full += 1;
                }
            }
            assert!(empty > 0 && full > 5);
        });
    }

    #[test]
    fn a_file_named_as_a_directory_lists_once_as_the_directory() {
        let paths = nested_paths();
        let packed = packed_ids(&paths);
        with_view(&paths, &packed, |v, img| {
            for (key, name) in [(&b"/app0/data"[..], &b"s1"[..]), (b"/app0/data/s2", b"d1")] {
                let dir = v.dirs_by_hash(crate::idx_path_hash(key)).next().unwrap();
                assert_eq!(listed(&v, img, dir, v.first(dir)).get(name), Some(&true));
            }
            let only = v
                .dirs_by_hash(crate::idx_path_hash(b"/app0/only"))
                .next()
                .unwrap();
            let got = listed(&v, img, only, v.first(only));
            assert_eq!((got.len(), got.get(&b"2"[..])), (1, Some(&false)));
        });
    }

    #[test]
    fn a_directory_with_nothing_packed_lists_nothing() {
        let paths = nested_paths();
        with_view(
            &paths,
            |_| false,
            |v, _| {
                for dir in 0..=v.dir_count() + 1 {
                    assert_eq!(v.first(dir), Cursor::Done);
                }
                assert_eq!(v.next(Cursor::Done), (None, Cursor::Done));
            },
        );
    }

    #[test]
    fn a_cursor_taken_midway_resumes_and_first_rewinds() {
        let paths = nested_paths();
        let packed = packed_ids(&paths);
        with_view(&paths, &packed, |v, img| {
            let root = v
                .dirs_by_hash(crate::idx_path_hash(b"/app0"))
                .next()
                .unwrap();
            let all = listed(&v, img, root, v.first(root));
            let (_, mid) = v.next(v.first(root));
            let (head, _) = v.next(v.first(root));
            let mut rest = listed(&v, img, root, mid);
            assert_eq!(rest.len() + 1, all.len());
            let mut buf = [0u8; PATH_BUF];
            let name = match head.unwrap() {
                Entry::Dir(d) => v.dir_path(img, d, &mut buf).unwrap()[6..].to_vec(),
                Entry::File(f) => v.path(img, f, &mut buf).unwrap()[6..].to_vec(),
            };
            rest.insert(
                name.to_ascii_lowercase(),
                matches!(head, Some(Entry::Dir(_))),
            );
            assert_eq!(rest, all);
            assert_eq!(listed(&v, img, root, v.first(root)), all);
        });
    }
}
