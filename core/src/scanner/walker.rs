use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// The core file traversal engine.
pub struct MonorepoWalker {
    root_path: PathBuf,
}

impl MonorepoWalker {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            root_path: path.as_ref().to_path_buf(),
        }
    }

    /// Yields all valid files in the monorepo, respecting .gitignore
    /// and skipping hidden directories, optimized for fast parallel collection.
    pub fn collect_files(&self) -> Vec<PathBuf> {
        let mut builder = WalkBuilder::new(&self.root_path);
        
        // Ensure standard exclusion rules while scanning CI configs (.github, .gitlab) and .env
        builder.hidden(false)
               .follow_links(false)
               .max_depth(Some(50))
               .git_ignore(true)
               .git_global(true)
               .git_exclude(true)
               .add_custom_ignore_filename(".gitignore")
               .add_custom_ignore_filename(".pqcanaryignore")
               .filter_entry(|entry| {
                   if let Some(name) = entry.file_name().to_str() {
                       if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                           // Skip internal VCS directories, IDE caches, and build folders
                           if name == ".git" || name == ".svn" || name == ".hg" || name == ".idea"
                               || name == ".vscode" || name == "node_modules" || name.starts_with("target")
                               || name == "dist" || name == "build" || name == ".next" || name == "out"
                               || name == ".vinxi" || name == ".output" || name == ".turbo" || name == ".cache"
                               || name == "vendor" || name == ".notes" || name == "inspiration"
                               || name == "artei-main"
                           {
                               return false;
                           }
                       }
                   }
                   true
               });

        let mut files = Vec::new();

        for entry in builder.build().flatten() {
            if entry.file_type().is_some_and(|ft| ft.is_file()) {
                files.push(entry.into_path());
            }
        }

        files
    }
}
