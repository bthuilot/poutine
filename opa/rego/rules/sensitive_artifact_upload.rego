# METADATA
# title: Upload of Sensitive Artifact
# description: |-
#   The workflow uploads a sensitive artifact to a GitHub repository.
# custom:
#   level: error
package rules.sensitive_artifact_upload

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

_upload_git_folder(step) if {
    some i
    step.uses == "actions/upload-artifact@v4"
    step["with"][i].name == "path"
    lines := split(step["with"][i].value, "\n")
    lines[_] == "."
    startswith(lines[_], "!.git")
#    step["with"][i].value == "."
}


results contains poutine.finding(rule, pkg.purl, {
    "path": workflow.path,
    "job": job.id,
    "step": step,
    "details": "Sensitive artifact uploaded",
}) if {
    pkg := input.packages[_]
    workflow := pkg.github_actions_workflows[_]
    job := workflow.jobs[_]
    step := job.steps[i]
    _upload_git_folder(step)
}