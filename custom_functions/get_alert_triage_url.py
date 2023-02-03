def get_alert_triage_url(asset=None, alert_id=None, **kwargs):
    """
    Gets URL of alert triage page in CBC console given configuration asset and alert id
    
    Args:
        asset (CEF type: *): configuration asset name or id
        alert_id (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        console_url (CEF type: *): URL to console
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    try:
        url = phantom.build_phantom_rest_url('asset')
        asset = asset[0]
        params = {'name': asset, 'page_size': 10000}
        response = phantom.requests.get(uri=url, params=params, verify=False).json()
        names = ""

        for entry in response["data"]:
            if entry["name"] == asset:
                cbc_url = entry["configuration"]["cbc_url"]
    except:
        pass
    
    try:
        console_url = "{}/triage?alertId={}".format(cbc_url.rstrip("/"), alert_id[0])
    except:
        console_url = ""

    outputs = {"console_url": console_url}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
