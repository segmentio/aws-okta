useragent
=========
[![GoDoc](https://godoc.org/github.com/beiriannydd/useragent?status.svg)](https://godoc.org/github.com/beiriannydd/useragent)
[![GolangCI](https://golangci.com/badges/github.com/beiriannydd/useragent.svg)](https://golangci.com)
[![License](https://img.shields.io/github/license/beiriannydd/useragent)](/LICENSE)
[![Release](https://img.shields.io/github/release/beiriannydd/useragent.svg)](https://github.com/beiriannydd/useragent/releases/latest)


A better user agent string for web requests.

You may want to be able to tell what OS/Arch is being used for your requests.
You may want to be able to have something more specific than "Go-http-client/1.1"

`agent := useragent.DefaultUserAgent` will return the default User-Agent string with the addition of
some architecture specific strings from Mozilla/Chrome in parenthesis.

If you want to add more information about your client

`agent := useragent.NewUserAgent("myagent/1.0", "client/2.5 (myagent)")` can be used like DefaultUserAgent.

The `UserAgent` struct implements the `Stringer` interface `func String() string`.

    import (
      "net/http"
      "os"

      "github.com/beiriannydd/useragent"
    )

    func main() {
      agent := useragent.NewUserAgent("myagent/1.0", "client/2.5 (myagent)")
      req := http.NewRequest("GET","/",nil)
      req.Header.Add("User-Agent", agent.String())
      req.Write(os.Stdout)
    }
