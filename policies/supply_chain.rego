package supply_chain

default allow = false

allow {
    count(deny) == 0
}

deny[msg] {
    input.runs_as_root == true
    msg := "Container must not run as root"
}

deny[msg] {
    input.has_secrets_in_env == true
    msg := "Secrets must not be stored in environment variables"
}

deny[msg] {
    not input.commit_sha
    msg := "Build must originate from a tracked source commit"
}

deny[msg] {
    not input.build_id
    msg := "Build must originate from a managed Cloud Build pipeline"
}
