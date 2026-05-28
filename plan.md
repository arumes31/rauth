1. **Optimize `ListUsers` in `internal/core/user.go`**
   - Write a python script to patch `ListUsers` in `internal/core/user.go` to use `UserDB.Pipeline()` and batch `HGetAll` calls.
   - Run the script with `python3 patch.py` via `run_in_bash_session`.
2. **Verify changes**
   - Run `go test -v ./internal/core/...` to ensure the `ListUsers` function behaves correctly.
3. **Complete pre commit steps**
   - Complete pre commit steps to make sure proper testing, verifications, reviews and reflections are done.
4. **Submit changes**
   - Call the `submit` tool with `branch_name`, `commit_message`, `title` and `description` to create a PR for the performance improvement.
