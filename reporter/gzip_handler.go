package main

import (
	"compress/gzip"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func supportsGzip(header string) bool {
	for _, format := range strings.Split(header, ",") {
		format = strings.TrimSpace(strings.SplitN(format, ";", 2)[0])
		if format == "gzip" {
			return true
		}
	}
	return false
}

type GzipResponseWriter struct {
	http.ResponseWriter
	gzipWriter *gzip.Writer
}

func NewGzipResponseWriter(w http.ResponseWriter) *GzipResponseWriter {
	return &GzipResponseWriter{w, gzip.NewWriter(w)}
}

func (w *GzipResponseWriter) Write(data []byte) (int, error) {
	return w.gzipWriter.Write(data)
}

func (w *GzipResponseWriter) WriteHeader(code int) {
	if code >= 300 {
		// OK and Partial Content may keep Content-Encoding, but Not
		// Modified does not have any content.
		w.Header().Del("Content-Encoding")
	}
	w.ResponseWriter.WriteHeader(code)
}

func StaticFileGz(group gin.IRoutes, relativePath, filepath string) {
	handler := func(c *gin.Context) {
		if supportsGzip(c.GetHeader("Accept-Encoding")) {
			info, err := os.Stat(filepath)
			if err != nil {
				// file must exist or router is misconfigured.
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			rangeHeader := c.GetHeader("Range")
			// serve pre-compressed gzip file if possible
			// Partial ranges require recompression.
			if rangeHeader == "" {
				nameGz := filepath + ".gz"
				if gzFile, err := os.Open(nameGz); err == nil {
					defer gzFile.Close()
					c.Header("Content-Encoding", "gzip")
					http.ServeContent(c.Writer, c.Request, nameGz, info.ModTime(), gzFile)
					return
				}
			}

			// compress only existing files that are worth
			// compressing (i.e. larger than a certain limit).
			if info, _ := os.Stat(filepath); info.Size() >= 1024 {
				c.Header("Content-Encoding", "gzip")
				gzipResponseWriter := NewGzipResponseWriter(c.Writer)
				http.ServeFile(gzipResponseWriter, c.Request, filepath)
				gzipResponseWriter.gzipWriter.Flush()
				gzipResponseWriter.gzipWriter.Close()
				return
			}
		}

		// serve uncompressed file
		c.File(filepath)
	}

	group.GET(relativePath, handler)
	group.HEAD(relativePath, handler)
}
