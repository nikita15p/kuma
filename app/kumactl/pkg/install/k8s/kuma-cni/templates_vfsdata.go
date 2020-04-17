// Code generated by vfsgen; DO NOT EDIT.

// +build !dev

package kumacni

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	pathpkg "path"
	"time"
)

// Templates statically implements the virtual filesystem provided to vfsgen.
var Templates = func() http.FileSystem {
	fs := vfsgen۰FS{
		"/": &vfsgen۰DirInfo{
			name:    "/",
			modTime: time.Date(2020, 4, 17, 18, 18, 0, 760386147, time.UTC),
		},
		"/all-in-one-template.yaml": &vfsgen۰CompressedFileInfo{
			name:             "all-in-one-template.yaml",
			modTime:          time.Date(2020, 4, 17, 18, 18, 0, 760048588, time.UTC),
			uncompressedSize: 3775,

			compressedContent: []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xa4\x56\xcf\x6f\xdb\xb8\x12\xbe\xfb\xaf\x18\xb8\x87\x5e\x22\xeb\x15\x0f\x0f\x28\xf4\x4e\xa9\x9b\xa6\x46\x1a\x37\x48\x9a\xdd\x43\x51\x08\x23\x72\x6c\x71\x4d\x71\x08\x92\x72\xe2\xee\xee\xff\xbe\xa0\x7e\x38\x92\x63\xa7\x45\x57\x07\x1b\x12\x67\xbe\xf9\x38\x33\xfc\x38\x49\x92\x4c\xd0\xaa\xdf\xc8\x79\xc5\x26\x83\xed\x9b\xc9\x46\x19\x99\xc1\x1d\xb9\xad\x12\x74\x2e\x04\xd7\x26\x4c\x2a\x0a\x28\x31\x60\x36\x01\x30\x58\x51\x06\x9b\xba\xc2\x44\x18\xd5\x7d\xf0\x16\x45\xf3\xb5\xa0\xc4\xef\x7c\xa0\x6a\x02\xa0\xb1\x20\xed\xa3\x0f\x00\x5a\x3b\x70\x8a\x71\xdb\x40\x73\x36\x2b\xb5\xbe\x46\x7b\xc8\xe3\x74\xc8\x44\x34\x3e\xbf\x16\xb9\x87\x7c\x05\x5f\x4a\x82\xf9\x72\x01\x86\xc2\x03\xbb\x0d\xb4\xa8\xb5\xc3\xa0\xd8\x40\x60\x40\x29\xe3\x5f\x28\x09\xac\xae\xd7\xca\x80\x28\x51\x19\x60\x03\x84\xa2\x04\xc3\x92\x66\xd0\xe0\x78\x4b\x42\xa1\x6e\x70\xb7\xa8\x6b\xf2\xa0\x0c\x84\x52\xf9\x0e\x16\x1e\x94\xd6\x50\x10\x60\x1d\xb8\xc2\xa0\x04\x6a\xbd\x03\xcb\xb6\xd6\x18\x48\xce\x26\x00\xc2\xa8\xbc\x23\x93\xb7\x5e\x19\xfc\x95\x34\x7b\xf8\xb3\xf9\x05\x98\x0a\xd3\x27\x69\x9a\xc1\xf4\x3f\xb3\xff\xce\xde\x4c\xcf\xfa\xc5\x98\x8e\xf8\xb9\xdf\xec\xd3\x4a\xd8\xd9\x13\x2b\x9a\xd7\xb9\xa6\x2d\xe9\xb8\xac\xcc\x8a\x9f\x96\x62\x4a\x9d\xa1\x40\x7e\x9a\xed\x19\xec\x57\x5a\x86\xd1\x2b\xcf\xaf\xee\xdf\x5d\xcc\x3f\x2f\x3f\x2c\x2e\xf3\x0f\x8b\x4f\x17\x37\xe7\x5f\x3e\xe6\xf9\x1e\xa8\x27\x9e\x17\xca\xe4\x52\xb9\xe8\x93\x6e\xd1\xa5\x5a\x15\xa9\x30\x2a\x2d\x94\x19\x1b\xd3\xa3\xd0\xb5\xa4\x7c\x5f\xdf\xc8\xe0\x6b\x1b\xb7\x2b\xf2\x14\xbe\x75\x1e\x7f\x4f\xda\xdf\xc3\x5e\x76\x05\x8a\x19\xd6\xa1\x64\xa7\xbe\x37\x45\x9d\x6d\xde\xfa\x99\xe2\x74\xdf\xe5\x73\x5d\xfb\x40\xee\x96\x35\xbd\xdc\xe2\xa7\xfb\xc9\xd5\x9a\x9a\x85\x04\xd0\xaa\x4b\xc7\xb5\xf5\x19\x7c\x9d\x4e\x5b\x7a\x8e\x3c\xd7\x4e\x50\xe7\x1b\xcd\x2c\x4b\xbf\x7f\x89\x3d\xd4\xbe\x6d\xc9\x15\x03\xab\x35\x85\x7f\xb9\xa3\x77\xca\x48\x65\xd6\xbf\xbc\x31\xd6\x74\x4b\xab\xb8\xd4\x6f\xec\x05\x06\x13\x80\xe7\x29\x7d\x16\xcf\xd7\xc5\x1f\x24\x42\x97\xaf\xa3\x4a\x13\x89\x3c\x63\x79\xf2\xa4\x3f\xe9\xc8\x7b\xa4\x8a\xcd\x1d\x85\x51\xc6\xd0\x5a\x9f\xbe\x2c\x26\xb1\x02\x3f\x2b\x25\x9b\xb7\x3e\x19\x65\xa9\xf5\x8e\xa7\x3f\x1a\x78\xd2\x24\x02\xbb\xd6\xb8\xc2\x20\xca\x4f\x03\xef\x93\xfe\x00\xb5\x95\x18\xe8\x2e\x38\x0c\xb4\xde\xb5\xe6\xf1\xcc\x66\x70\xcb\x5a\x2b\xb3\xbe\x6f\x0c\xda\x96\x1a\x7e\xe9\x91\x2b\x7c\xbc\x37\xb8\x45\xa5\xb1\xd0\x94\xc1\x9b\x09\x40\xa0\xca\xea\xbd\xcd\x30\x05\xf1\xd1\x23\x66\x2f\x70\x6b\x5a\xc3\x18\x0e\x4d\xbd\x07\x1e\x51\x42\x95\x3f\x03\xd4\x6c\xa2\xc0\x85\xb2\xd1\xca\xb9\x53\x8d\xbc\x9d\x4b\xc9\xc6\x7f\x36\x7a\x07\x81\x35\x75\xba\x5a\x90\xe6\x87\xb3\x01\x46\x85\x6e\xe3\x5b\x91\x65\x09\xe8\x01\x41\x74\x08\x51\x81\x13\x36\x67\x40\xc6\xd7\x4e\x99\x35\xa8\x10\x0f\x86\x1f\xb8\x5b\xa7\xd8\xa9\xb0\x03\x2f\x4a\x92\x75\xcc\x0c\xa0\x91\x10\x4a\x0c\xa0\x82\x7f\x3a\x81\x80\x8e\xe2\x1b\xb9\x2d\xc9\x01\x82\x5a\x45\x58\xda\x92\x6b\xb0\x81\xb6\x4a\x74\x8a\xdc\x3e\x1d\x32\xb9\x19\x6a\x5b\xe2\xec\x49\x17\xe3\xd1\xeb\xc9\x26\x96\x65\x06\xaf\x5f\x37\x6e\x7d\x47\x34\xad\xcb\x92\xee\x46\x9d\x11\x9f\x82\xc2\x21\x12\xfb\x0c\xb4\x32\xf5\x63\x67\x54\xb2\x0f\xcb\xf6\x3e\xc8\x20\xb8\xba\x2f\xc6\x53\x36\x47\xc5\xb8\xc6\x0d\x81\xaf\x1d\x8d\x2b\xd8\x6e\xaa\xdf\x83\x8c\xb7\x17\x6a\xdd\x0a\xcf\xd3\x1e\x13\xa0\xd5\x8a\x44\xc8\x60\xc9\x77\x9d\xed\x40\x91\xd9\xc6\x88\xec\x32\xb8\x78\x54\x7e\x54\x80\x6b\x74\x9b\x17\xcb\x07\x2b\x76\x31\xef\xfb\xfa\x0c\xa3\x6e\x68\x97\x1d\xe9\x98\x9f\x09\x3d\xa4\x7c\xf1\x48\xa2\x0e\x3f\xc1\xb8\x6f\x97\xb9\x46\xef\x97\x8d\x12\xb4\x27\x3d\x11\xad\x70\x25\x3d\xfb\xce\xc1\x8f\xe4\x69\xf9\x5c\x99\x9a\x1c\x28\xa3\x2a\xf5\x9d\x40\xf2\x83\x09\xaa\x22\x90\x6d\xbf\x62\x7f\x5a\xa1\xb6\x6b\x87\x92\x80\x1d\x48\xd2\x14\xab\xf7\x7f\x08\xa4\x35\x5c\xed\x9b\x20\x4e\x1b\x92\x01\x61\xba\x62\x27\x68\x0f\xdf\x3b\x4c\x33\x28\x43\xb0\x3e\x4b\xd3\x71\xe7\x48\x16\x3e\x15\x6c\x04\xd9\xe0\xd3\xd8\x30\x9a\x51\xfa\x34\x5e\x35\xf1\x27\x7d\x15\xc8\x55\xca\x34\x4d\x93\xf0\x2a\xf6\xea\xbe\xf8\x83\xa5\x4b\x87\x82\x6e\xc8\x29\x96\x77\xf1\x82\x97\x3e\x83\xff\x75\x66\x82\x4d\x40\x65\xc8\x0d\x9a\x2e\xe9\xc4\x54\x19\x1f\x50\xeb\x41\x4e\xe2\xa3\x2a\x5c\x53\x16\x47\x8c\x62\xc3\x5b\xa5\x77\x98\x0e\x0c\xb3\xfd\x2c\x72\xe8\x72\x53\x6b\x7d\xc3\x5a\x89\x5d\x06\xe7\xfa\x01\x77\x7e\x60\x21\xb8\xaa\x30\x0a\xfe\xd7\xe9\x10\x6d\xe6\xcb\xe9\xb7\x81\x19\x99\x6d\x36\x78\x8d\x59\x8c\xb5\x03\x5e\xb5\x1a\xb5\x5c\xf4\x83\xd9\x4a\x69\x8a\x89\x17\x8e\x30\xd0\x6c\xe4\xd4\xef\x6f\xbe\x5c\xe4\x71\xbe\xc9\x97\xe7\xd7\x17\x23\x0b\x68\xc7\xbd\xc1\x68\x35\x8b\xb8\xd3\x83\xd8\xc7\x67\xcd\x18\xb6\xdb\xc3\x78\xa8\x3c\x49\x62\x79\xf1\xe5\xf7\xcf\xb7\x57\x79\x3b\x6c\x1d\x63\xf2\xc1\x71\x95\x1d\x2c\x40\x17\xef\x1a\xed\x15\xed\xba\x4b\xfd\xf0\x39\x35\x63\x1f\x3e\xcd\x89\x7d\x3e\xaa\xbe\x44\x39\x7f\xbf\xb8\x3d\x9e\xb5\x94\x82\x68\x46\xc0\xaa\xd6\xa1\xf6\xa9\xa1\x30\x93\x07\xb9\x5b\xac\x1a\xf1\x3b\x03\x49\x56\xf3\xae\xd3\x98\x38\x89\x93\x6c\x92\xda\x0e\xe7\x67\xc0\xa1\x24\xf7\xa0\x3c\x8d\x2c\x7d\x40\x23\xe3\x15\xd5\x54\xe0\x38\xcd\x8f\xe7\x8b\xe5\xc5\xfb\x3c\xd2\xbd\xf9\x74\x7f\xb9\x58\x9e\xa8\xf1\x0a\xb5\xa7\x61\x6d\xb7\xac\xeb\x8a\xae\xa3\x34\xf8\xec\x00\xbb\x8a\x5f\x6f\x30\x94\x19\xa4\x51\xca\x53\xb6\xa1\x1f\x77\x27\xc7\x72\x1f\xd3\x5e\x28\x93\x48\xe5\x7e\x04\xd5\xa7\xed\x79\xbe\x86\x60\x86\xc2\x00\xac\xe5\x3a\xba\x32\xee\x3d\xc9\x61\x13\xce\x97\x8b\xd9\xb3\xc3\x7d\x9c\x56\xa4\xd1\x30\x1a\x45\xb7\x2d\xc7\x83\xe1\xfe\x28\xe4\x98\xdc\x0f\x21\x8f\x36\xca\x3f\x01\x00\x00\xff\xff\xc3\x22\x1c\x1f\xbf\x0e\x00\x00"),
		},
	}
	fs["/"].(*vfsgen۰DirInfo).entries = []os.FileInfo{
		fs["/all-in-one-template.yaml"].(os.FileInfo),
	}

	return fs
}()

type vfsgen۰FS map[string]interface{}

func (fs vfsgen۰FS) Open(path string) (http.File, error) {
	path = pathpkg.Clean("/" + path)
	f, ok := fs[path]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}

	switch f := f.(type) {
	case *vfsgen۰CompressedFileInfo:
		gr, err := gzip.NewReader(bytes.NewReader(f.compressedContent))
		if err != nil {
			// This should never happen because we generate the gzip bytes such that they are always valid.
			panic("unexpected error reading own gzip compressed bytes: " + err.Error())
		}
		return &vfsgen۰CompressedFile{
			vfsgen۰CompressedFileInfo: f,
			gr:                        gr,
		}, nil
	case *vfsgen۰DirInfo:
		return &vfsgen۰Dir{
			vfsgen۰DirInfo: f,
		}, nil
	default:
		// This should never happen because we generate only the above types.
		panic(fmt.Sprintf("unexpected type %T", f))
	}
}

// vfsgen۰CompressedFileInfo is a static definition of a gzip compressed file.
type vfsgen۰CompressedFileInfo struct {
	name              string
	modTime           time.Time
	compressedContent []byte
	uncompressedSize  int64
}

func (f *vfsgen۰CompressedFileInfo) Readdir(count int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("cannot Readdir from file %s", f.name)
}
func (f *vfsgen۰CompressedFileInfo) Stat() (os.FileInfo, error) { return f, nil }

func (f *vfsgen۰CompressedFileInfo) GzipBytes() []byte {
	return f.compressedContent
}

func (f *vfsgen۰CompressedFileInfo) Name() string       { return f.name }
func (f *vfsgen۰CompressedFileInfo) Size() int64        { return f.uncompressedSize }
func (f *vfsgen۰CompressedFileInfo) Mode() os.FileMode  { return 0444 }
func (f *vfsgen۰CompressedFileInfo) ModTime() time.Time { return f.modTime }
func (f *vfsgen۰CompressedFileInfo) IsDir() bool        { return false }
func (f *vfsgen۰CompressedFileInfo) Sys() interface{}   { return nil }

// vfsgen۰CompressedFile is an opened compressedFile instance.
type vfsgen۰CompressedFile struct {
	*vfsgen۰CompressedFileInfo
	gr      *gzip.Reader
	grPos   int64 // Actual gr uncompressed position.
	seekPos int64 // Seek uncompressed position.
}

func (f *vfsgen۰CompressedFile) Read(p []byte) (n int, err error) {
	if f.grPos > f.seekPos {
		// Rewind to beginning.
		err = f.gr.Reset(bytes.NewReader(f.compressedContent))
		if err != nil {
			return 0, err
		}
		f.grPos = 0
	}
	if f.grPos < f.seekPos {
		// Fast-forward.
		_, err = io.CopyN(ioutil.Discard, f.gr, f.seekPos-f.grPos)
		if err != nil {
			return 0, err
		}
		f.grPos = f.seekPos
	}
	n, err = f.gr.Read(p)
	f.grPos += int64(n)
	f.seekPos = f.grPos
	return n, err
}
func (f *vfsgen۰CompressedFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		f.seekPos = 0 + offset
	case io.SeekCurrent:
		f.seekPos += offset
	case io.SeekEnd:
		f.seekPos = f.uncompressedSize + offset
	default:
		panic(fmt.Errorf("invalid whence value: %v", whence))
	}
	return f.seekPos, nil
}
func (f *vfsgen۰CompressedFile) Close() error {
	return f.gr.Close()
}

// vfsgen۰DirInfo is a static definition of a directory.
type vfsgen۰DirInfo struct {
	name    string
	modTime time.Time
	entries []os.FileInfo
}

func (d *vfsgen۰DirInfo) Read([]byte) (int, error) {
	return 0, fmt.Errorf("cannot Read from directory %s", d.name)
}
func (d *vfsgen۰DirInfo) Close() error               { return nil }
func (d *vfsgen۰DirInfo) Stat() (os.FileInfo, error) { return d, nil }

func (d *vfsgen۰DirInfo) Name() string       { return d.name }
func (d *vfsgen۰DirInfo) Size() int64        { return 0 }
func (d *vfsgen۰DirInfo) Mode() os.FileMode  { return 0755 | os.ModeDir }
func (d *vfsgen۰DirInfo) ModTime() time.Time { return d.modTime }
func (d *vfsgen۰DirInfo) IsDir() bool        { return true }
func (d *vfsgen۰DirInfo) Sys() interface{}   { return nil }

// vfsgen۰Dir is an opened dir instance.
type vfsgen۰Dir struct {
	*vfsgen۰DirInfo
	pos int // Position within entries for Seek and Readdir.
}

func (d *vfsgen۰Dir) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && whence == io.SeekStart {
		d.pos = 0
		return 0, nil
	}
	return 0, fmt.Errorf("unsupported Seek in directory %s", d.name)
}

func (d *vfsgen۰Dir) Readdir(count int) ([]os.FileInfo, error) {
	if d.pos >= len(d.entries) && count > 0 {
		return nil, io.EOF
	}
	if count <= 0 || count > len(d.entries)-d.pos {
		count = len(d.entries) - d.pos
	}
	e := d.entries[d.pos : d.pos+count]
	d.pos += count
	return e, nil
}