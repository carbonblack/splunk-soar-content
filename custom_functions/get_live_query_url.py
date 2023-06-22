def get_live_query_url(asset=None, device_id=None, **kwargs):
    """
    Get URL to Live Response
    
    Args:
        asset
        device_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        console_url
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    err=""
    try:
        url = phantom.build_phantom_rest_url('asset')
        params = {'name': asset, 'page_size': 10000}
        response = phantom.requests.get(uri=url, params=params, verify=False).json()
        names = ""

        for entry in response["data"]:
            if entry["name"] == asset:
                cbc_url = entry["configuration"]["cbc_url"]
    except:
        import traceback
        err += traceback.format_exc()
        pass
    
    try:
        console_url = "{}/live-response/{}".format(cbc_url.rstrip("/"), device_id[0])
    except:
        import traceback
        err += traceback.format_exc()
        console_url = err

    outputs = {"console_url": console_url}
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
