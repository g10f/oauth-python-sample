# Get oidc-config
$ = django.jQuery
$ ->
  $("input[name='openid-configuration']").click ->
    url = $("input[name='issuer']").val()
    if (url isnt '')
      url = url + "/.well-known/openid-configuration"
      $.ajax(
        type: 'GET',
        url: url
      )
      .done (oid_config) ->
        if (console and console.log)
          console.log("data:", oid_config)
        $("input[name='authorization_endpoint']").val(oid_config.authorization_endpoint)
        $("input[name='token_endpoint']").val(oid_config.token_endpoint)
        $("input[name='end_session_endpoint']").val(oid_config.end_session_endpoint)
        # $("input[name='revoke_uri']").val(oid_config.revoke_uri)
        $("input[name='userinfo_endpoint']").val(oid_config.userinfo_endpoint)
        $("input[name='certs_uri']").val(oid_config.jwks_uri)
        $("input[name='profile_uri']").val(oid_config.profile_uri)
        $("input[name='check_session_iframe']").val(oid_config.check_session_iframe)
        $("input[name='jwks_uri']").val(oid_config.jwks_uri)
      .fail ->
        console.log("Sorry. Service unavailable.")





