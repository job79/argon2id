Small wrapper around the argon2id class that
appends the used parameters to the calculated
hash. This makes it possible to change the parameters
without effecting previously stored hashes.

Example:
```go
opts := Options{
	Memory:   64 * 1024,
	Time:     1,
	Threads:  2,
	KeySize:  32,
	SaltSize: 10,
}

hash, _ := argon2.Hash(opts, []byte("password"))
ok, _ := argon2.Verify([]byte("password"), hash)
fmt.Println(hash, ok)
```
