package http

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/filebrowser/filebrowser/v2/files"
)

var withHashFile = func(fn handleFunc) handleFunc {
	deepAllowed := 3
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		rawPath := r.URL.Path
		splited := strings.Split(r.URL.Path, "/")
		if len(splited) == deepAllowed {
			r.URL.Path = strings.Join(splited[:2], "/")
		}
		link, err := d.store.Share.GetByHash(r.URL.Path)
		if err != nil {
			link, err = d.store.Share.GetByHash(ifPathWithName(r))
			if err != nil {
				return errToStatus(err), err
			}
		}
		r.URL.Path = rawPath

		user, err := d.store.Users.Get(d.server.Root, link.UserID)
		if err != nil {
			return errToStatus(err), err
		}

		d.user = user

		if len(splited) == deepAllowed {
			link.Path = filepath.Join(link.Path, splited[2])
		}

		file, err := files.NewFileInfo(files.FileOptions{
			Fs:      d.user.Fs,
			Path:    link.Path,
			Modify:  d.user.Perm.Modify,
			Expand:  true,
			Checker: d,
		})
		if err != nil {
			return errToStatus(err), err
		}

		d.raw = file
		return fn(w, r, d)
	}
}

// ref to https://github.com/filebrowser/filebrowser/pull/727
// `/api/public/dl/MEEuZK-v/file-name.txt` for old browsers to save file with correct name
func ifPathWithName(r *http.Request) string {
	pathElements := strings.Split(r.URL.Path, "/")
	// prevent maliciously constructed parameters like `/api/public/dl/XZzCDnK2_not_exists_hash_name`
	// len(pathElements) will be 1, and golang will panic `runtime error: index out of range`
	if len(pathElements) < 2 { //nolint: mnd
		return r.URL.Path
	}
	id := pathElements[len(pathElements)-2]
	return id
}

var publicShareHandler = withHashFile(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	file := d.raw.(*files.FileInfo)

	if file.IsDir {
		file.Listing.Sorting = files.Sorting{By: "name", Asc: false}
		file.Listing.ApplySort()
		return renderJSON(w, r, file)
	}

	return renderJSON(w, r, file)
})

var publicDlHandler = withHashFile(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	file := d.raw.(*files.FileInfo)
	if !file.IsDir {
		return rawFileHandler(w, r, file)
	}

	return rawDirHandler(w, r, d, file)
})
