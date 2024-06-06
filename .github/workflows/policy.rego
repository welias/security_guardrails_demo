package semgrep.policy

deny[msg] {
    result := input[_]
    result.extra.severity == "CRITICAL"
    msg := sprintf("Build failed due to a critical vulnerability: %s", [result.extra.message])
}
