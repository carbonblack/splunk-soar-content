"""
initial
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_asset_info_1' block
    get_asset_info_1(container=container)

    return

@phantom.playbook_block()
def get_asset_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_asset_info_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceExternalId","artifact:*.id"])

    parameters = []

    # build parameters list for 'get_asset_info_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "device_id": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get asset info", parameters=parameters, name="get_asset_info_1", assets=["dev01"], callback=prompt_action)

    return


@phantom.playbook_block()
def prompt_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_action() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Choose an action to run"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Choose Action",
            "options": {
                "type": "list",
                "choices": [
                    "Pivot to a LiveResponse session",
                    "Kill a process on the endpoint",
                    "Quarantine/Unquarantine",
                    "Ban/Unban process hash",
                    "Dismiss alert"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_action", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'elif' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action:action_result.summary.responses.0", "==", "Kill a process on the endpoint"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        kill_process_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action:action_result.summary.responses.0", "==", "Pivot to a LiveResponse session"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        get_live_query_url_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action:action_result.summary.responses.0", "==", "Ban/Unban process hash"]
        ])

    # call connected blocks if condition 3 matched
    if found_match_3:
        prompt_ban(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 4
    found_match_4 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action:action_result.summary.responses.0", "==", "Quarantine/Unquarantine"]
        ])

    # call connected blocks if condition 4 matched
    if found_match_4:
        prompt_quarantine(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 5
    found_match_5 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_action:action_result.summary.responses.0", "==", "Dismiss alert"]
        ])

    # call connected blocks if condition 5 matched
    if found_match_5:
        prompt_dismiss(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Please click [Here]({0})  for Process Analysis. Add a comment below."""

    # parameter list for template variable replacement
    parameters = [
        "get_live_query_url_2:custom_function_result.data.console_url"
    ]

    # responses
    response_types = [
        {
            "prompt": "Enter comment",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters, response_types=response_types)

    return


@phantom.playbook_block()
def kill_process_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("kill_process_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceExternalId","artifact:*.cef.process_guid","artifact:*.cef.destinationProcessName","artifact:*.id"])

    parameters = []

    # build parameters list for 'kill_process_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "device_id": container_artifact_item[0],
                "process_guid": container_artifact_item[1],
                "process_name": container_artifact_item[2],
                "context": {'artifact_id': container_artifact_item[3]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("kill process", parameters=parameters, name="kill_process_1", assets=["dev01"])

    return


@phantom.playbook_block()
def prompt_ban(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_ban() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Ban or unban process hash"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Choose action",
            "options": {
                "type": "list",
                "choices": [
                    "Ban process hash",
                    "Unban process hash"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_ban", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_ban:action_result.summary.responses.0", "==", "Ban process hash"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        ban_hash_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_ban:action_result.summary.responses.0", "==", "Unban process hash"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        unban_hash_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def ban_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ban_hash_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.threat_cause_actor_sha256","artifact:*.id"])

    parameters = []

    # build parameters list for 'ban_hash_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "process_hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ban hash", parameters=parameters, name="ban_hash_1", assets=["dev01"])

    return


@phantom.playbook_block()
def unban_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("unban_hash_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.threat_cause_actor_sha256","artifact:*.id"])

    parameters = []

    # build parameters list for 'unban_hash_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "process_hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("unban hash", parameters=parameters, name="unban_hash_1", assets=["dev01"])

    return


@phantom.playbook_block()
def prompt_quarantine(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_quarantine() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Quarantine or unquarantine device"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Choose action",
            "options": {
                "type": "list",
                "choices": [
                    "Quarantine",
                    "Unquarantine"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_quarantine", parameters=parameters, response_types=response_types, callback=decision_4)

    return


@phantom.playbook_block()
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_4() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_quarantine:action_result.summary.responses.0", "==", "Quarantine"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        quarantine_device_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_quarantine:action_result.summary.responses.0", "==", "Unquarantine"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        unquarantine_device_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("quarantine_device_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceExternalId","artifact:*.id"])

    parameters = []

    # build parameters list for 'quarantine_device_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "device_id": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("quarantine device", parameters=parameters, name="quarantine_device_1", assets=["dev01"])

    return


@phantom.playbook_block()
def unquarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("unquarantine_device_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceExternalId","artifact:*.id"])

    parameters = []

    # build parameters list for 'unquarantine_device_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "device_id": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("unquarantine device", parameters=parameters, name="unquarantine_device_1", assets=["dev01"])

    return


@phantom.playbook_block()
def prompt_dismiss(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_dismiss() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Dismiss this alert only or dismiss all future alerts with that threat_id?"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Choose Action",
            "options": {
                "type": "list",
                "choices": [
                    "Dismiss alert",
                    "Dismiss all future alerts"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_dismiss", parameters=parameters, response_types=response_types, callback=decision_5)

    return


@phantom.playbook_block()
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_5() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_dismiss:action_result.summary.responses.0", "==", "Dismiss alert"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dismiss_alert_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_dismiss:action_result.summary.responses.0", "==", "Dismiss all future alerts"]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        dismiss_future_alerts_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def dismiss_alert_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dismiss_alert_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.id","artifact:*.id"])

    parameters = []

    # build parameters list for 'dismiss_alert_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "alert_id": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("dismiss alert", parameters=parameters, name="dismiss_alert_1", assets=["dev01"])

    return


@phantom.playbook_block()
def get_live_query_url_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_live_query_url_2() called")

    asset_name_value = container.get("asset_name", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.deviceExternalId","artifact:*.id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "asset": asset_name_value,
        "device_id": container_artifact_cef_item_0,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="cbc-playbooks/get_live_query_url", parameters=parameters, name="get_live_query_url_2", callback=prompt_2)

    return


@phantom.playbook_block()
def dismiss_future_alerts_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dismiss_future_alerts_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.id","artifact:*.id"])

    parameters = []

    # build parameters list for 'dismiss_future_alerts_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "comment": "\"Dismissed by Splunk SOAR CBC App\"",
                "alert_id": container_artifact_item[0],
                "remediation_status": "\"fixed\"",
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("dismiss future alerts", parameters=parameters, name="dismiss_future_alerts_1", assets=["dev01"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return