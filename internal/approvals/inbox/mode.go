package inbox

import "io/fs"

// writableByOthers is the mode bits that let another account write a file or
// a directory.
const writableByOthers fs.FileMode = 0o022
