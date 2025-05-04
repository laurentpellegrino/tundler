package shared

import "log"

var debug bool

func SetDebug(v bool) { debug = v }

func Debugf(format string, v ...any) {
	if debug {
		log.Printf(format, v...)
	}
}
