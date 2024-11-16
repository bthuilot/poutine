# METADATA
# title: Upload of Sensitive Artifact
# description: |-
#   This rule detects when a sensitive artifact is uploaded using
#   the upload-artifact action.
# custom:
#   level: error
package rules.sensitive_artifact_upload

import data.poutine
import rego.v1

rule := poutine.rule(rego.metadata.chain())

_with_git_folder(step) if {
	step["with"][_].name == "path"
	step["with"][_].value == "."
}

_no_path_given(step) if {
	some withOpts in step["with"]
	withOpts.name == "path"
}

_with_git_folder(step) if {
	not _no_path_given(step)
}

results contains poutine.finding(rule, pkg.purl, {
	"path": workflow.path,
	"job": job.id,
	"step": i,
	"details": sprintf("'.git' folder is uploaded in step (%v)", [step.name]),
}) if {
	some i
	pkg := input.packages[_]
	workflow := pkg.github_actions_workflows[_]
	job := workflow.jobs[_]
	step := job.steps[i]
	contains(step.uses, "actions/upload-artifact@v4")
	_with_git_folder(step)
}
