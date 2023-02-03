# splunk-soar-content
A public repository for Splunk SOAR playbooks that use the VMware Carbon Black Cloud App.

## Overview:
The Carbon Black Cloud Alert Playbook strings together various actions to help you automate the orchestration and remediation of alerts in Carbon Black Cloud from within Splunk SOAR. There are basic actions for managing alerts and gathering endpoint information, and there are additional actions available per certain alert types.
For information about the Carbon Black Cloud Splunk App and how to use this playbook, visit the [Carbon Black Developer Network](http://developer.carbonblack.com/reference/carbon-black-cloud/integrations/splunk-soar)

## Configure the repository in Splunk SOAR

* In Splunk SOAR, go to the playbooks page
* Click the "Manage source control" button
* Under the "Repositories" drop-down select "Configure a new repository"
* Under "Repo URL" put "https://github.com/carbonblack/splunk-soar-content.git"
* Under "Branch name" put "main"
* Set a Repo Name (e.g "CBC playbooks")
* Leave "Username" and "Password" fields empty
* Click "Save"
* Back to the playbooks page click the "Update from source control" button
* On the "Source to update from" choose your newly created repository name